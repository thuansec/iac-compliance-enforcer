package terraform

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// DiagModuleWorkLimit reports a module instance that is not evaluated because the module tree
// used up its evaluation budget.
const DiagModuleWorkLimit DiagCode = "module_work_limit"

// Tree budgets (ADR 0009). Each module instance has the per-module budgets, and up to
// MaxModuleCalls instances would multiply them, so the tree has budgets of its own: an instance
// is evaluated only while every tree budget has some left, and charged after, so the tree uses
// at most each budget plus one module's per-module budget of that kind. Each kind is budgeted on
// its own, so no kind of work or memory passes about two modules' worth. maxTreeSource bounds
// the module source that child instances evaluate again (variable defaults, locals, resources;
// 200 to 630ns per byte); the root is always evaluated and not charged. maxTreeUnknownSteps
// bounds the steps of the unknown paths recorded for locals and resources, which hold memory
// (about 128 bytes per path) that their value units do not count.
const (
	maxTreeSource        = 1 << 23
	maxTreeFunctionWork  = maxFunctionWork
	maxTreeLocals        = maxLocalsSize
	maxTreeResources     = maxResourcesSize
	maxTreeInputs        = maxResourcesSize
	maxTreeReferences    = maxReferenceEntries
	maxTreeUnknownSteps  = 1 << 20
	maxTreeExpansionWork = maxExpansionWork
	maxTreeStructure     = maxInstanceStructure
	maxTreeInstances     = maxInstancesPerModule
)

// moduleUsage is what a module instance used of its value, reference and expansion budgets,
// and the steps of its unknown paths.
type moduleUsage struct {
	locals, resources, inputs, refs, unknown, expansion, structure, instances int
}

// treeUsage is what the instances of a tree used together.
type treeUsage struct {
	source, function int
	moduleUsage
}

// exhausted reports whether any tree budget is used up.
func (u treeUsage) exhausted() bool {
	return u.source >= maxTreeSource || u.function >= maxTreeFunctionWork ||
		u.locals >= maxTreeLocals || u.resources >= maxTreeResources || u.inputs >= maxTreeInputs ||
		u.refs >= maxTreeReferences || u.unknown >= maxTreeUnknownSteps ||
		u.expansion >= maxTreeExpansionWork || u.structure >= maxTreeStructure || u.instances >= maxTreeInstances
}

// usageOf returns what m has used so far, apart from its source.
func usageOf(m *ParsedModule) treeUsage {
	return treeUsage{function: m.fnWork, moduleUsage: m.usage}
}

// pathSteps counts the steps of paths, plus one per path.
func pathSteps(paths []cty.Path) int {
	n := len(paths)
	for _, p := range paths {
		n += len(p)
	}
	return n
}

// ModuleInstance is one evaluated module: the root or one resolved call.
type ModuleInstance struct {
	// Address is "" for the root, else the call's address; Dir is the module directory.
	Address, Dir string
	// Call is the module call, nil for the root.
	Call *ModuleCall
	// Module is the instance, which holds its evaluation diagnostics; parse diagnostics stay on
	// the tree's parse.
	Module *ParsedModule
	// Skipped reports that the tree's budget was used up before this instance: nothing in it
	// was evaluated, and its calls are not listed.
	Skipped   bool
	Variables map[string]Variable
	Locals    map[string]Local
	// Resources carry the instance's address in Module and as their address prefix.
	Resources []Resource
}

// treeEvaluator evaluates one ModuleTree.
type treeEvaluator struct {
	root    *fsutil.Root
	opts    VarOptions
	limits  Limits
	used    treeUsage
	charged map[*ParsedModule]treeUsage
	out     []*ModuleInstance
}

// EvaluateTree evaluates every resolved module of tree, depth first in call order: the root
// with its variables from defaults, tfvars and opts (EvaluateVariables), each child with its
// variables from its call's inputs evaluated in the caller (ModuleInputs), each in its own
// instance with its locals and resources. Module outputs are unknown to callers (T-0107h). Once
// the tree's budgets are used up, the remaining instances are Skipped with a module_work_limit
// warning at their call. Unresolved calls have no instance. Problems in the files are
// diagnostics; a file that cannot be read or a cancelled context is an error.
func EvaluateTree(ctx context.Context, root *fsutil.Root, tree *ModuleTree, opts VarOptions, limits Limits) ([]*ModuleInstance, error) {
	e := &treeEvaluator{root: root, opts: opts, limits: limits, charged: map[*ParsedModule]treeUsage{}}
	if err := e.evaluate(ctx, tree.Root, nil, nil); err != nil {
		return nil, fmt.Errorf("evaluate module tree: %w", err)
	}
	return e.out, nil
}

// evaluate evaluates node, loaded by call from caller (both nil for the root), then its calls.
func (e *treeEvaluator) evaluate(ctx context.Context, node *ModuleNode, call *ModuleCall, caller *ModuleInstance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	inst := &ModuleInstance{Address: node.Address, Dir: node.Dir, Call: call, Module: node.Module.NewInstance()}
	e.out = append(e.out, inst)
	m := inst.Module
	if caller != nil && e.used.exhausted() {
		inst.Skipped = true
		r := call.DefRange
		caller.Module.diag(SeverityWarning, DiagModuleWorkLimit, "Module tree too large to evaluate",
			"The module tree used up its evaluation budget, so this module instance and the modules it calls are not checked.",
			call.File, r.Start.Line, r.Start.Column)
		caller.Module.sortDiagnostics()
		return nil
	}
	if caller != nil {
		for _, data := range m.src {
			e.used.source += len(data)
		}
	}

	var err error
	if caller == nil {
		inst.Variables, err = m.EvaluateVariables(ctx, e.root, e.opts, e.limits)
	} else {
		var inputs map[string]Input
		inputs, err = caller.Module.ModuleInputs(ctx, call, caller.Variables, caller.Locals)
		e.charge(caller.Module)
		if err == nil {
			inst.Variables, err = m.EvaluateModuleVariables(ctx, call, inputs)
		}
	}
	if err != nil {
		return err
	}
	if inst.Locals, err = m.EvaluateLocals(ctx, inst.Variables); err != nil {
		return err
	}
	if inst.Resources, err = m.DecodeResources(ctx, inst.Variables, inst.Locals); err != nil {
		return err
	}
	if call != nil {
		for i := range inst.Resources {
			r := &inst.Resources[i]
			r.Module, r.CallFile, r.CallRange = node.Address, call.File, call.DefRange
			r.Address = node.Address + "." + r.Address
			r.BaseAddress = node.Address + "." + r.BaseAddress
		}
	}
	e.charge(m)

	for _, c := range node.Calls {
		if c.Child == nil {
			continue
		}
		if err := e.evaluate(ctx, c.Child, c, inst); err != nil {
			return err
		}
	}
	return nil
}

// charge adds what m used since it was last charged to the tree.
func (e *treeEvaluator) charge(m *ParsedModule) {
	now, before := usageOf(m), e.charged[m]
	u := &e.used
	u.function += now.function - before.function
	u.locals += now.locals - before.locals
	u.resources += now.resources - before.resources
	u.inputs += now.inputs - before.inputs
	u.refs += now.refs - before.refs
	u.unknown += now.unknown - before.unknown
	u.expansion += now.expansion - before.expansion
	u.structure += now.structure - before.structure
	u.instances += now.instances - before.instances
	e.charged[m] = now
}
