package terraform

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// DiagModuleWorkLimit reports a module instance that is not evaluated because the module tree
// used up its evaluation budget.
const DiagModuleWorkLimit DiagCode = "module_work_limit"

// Tree budgets (ADR 0009). Each module instance has the per-module budgets, and up to
// MaxModuleCalls instances would multiply them, so the tree has budgets of its own: an instance
// is evaluated only while every tree budget has some left, and charged after, so the tree uses
// at most each budget plus one module's per-module budget of that kind. Each kind is budgeted on
// its own, so no kind of work or memory passes about two modules' worth, except function work
// (four modules' worth, ADR 0021: about five with one instance's overshoot) and expansion work
// (four modules' worth, ADR 0022: about six, as an instance can add its expansion and its call
// arguments' expansion). maxTreeSource bounds the module source that child instances evaluate
// again (variable defaults, locals, resources; 200 to 630ns per byte); the root is always
// evaluated and not charged. maxTreeUnknownSteps
// bounds the steps of the unknown paths recorded for locals and resources, which hold memory
// (about 128 bytes per path) that their value units do not count.
const (
	maxTreeSource        = 1 << 23
	maxTreeFunctionWork  = 4 * maxFunctionWork // ADR 0021: for expressions charge it conservatively
	maxTreeLocals        = maxLocalsSize
	maxTreeResources     = maxResourcesSize
	maxTreeInputs        = maxResourcesSize
	maxTreeOutputs       = maxResourcesSize
	maxTreeReferences    = maxReferenceEntries
	maxTreeUnknownSteps  = 1 << 20
	maxTreeExpansionWork = 4 * maxExpansionWork // ADR 0022: realistic fan-out (T-0113d)
	maxTreeStructure     = maxInstanceStructure
	maxTreeInstances     = maxInstancesPerModule
	// maxTreeModuleInstances bounds the module instances of a tree: count and for_each on
	// nested calls multiply, and each instance holds its own state.
	maxTreeModuleInstances = 10_000
)

// moduleUsage is what a module instance used of its value, reference and expansion budgets,
// and the steps of its unknown paths.
type moduleUsage struct {
	locals, resources, inputs, outputs, refs, unknown, expansion, structure, instances int
	// callExpansion is the source of module call arguments evaluated again per instance, at
	// most maxExpansionWork (evaluateCall).
	callExpansion int
}

// treeUsage is what the instances of a tree used together.
type treeUsage struct {
	source, function int
	moduleUsage
}

// exhausted reports whether any tree budget is used up.
func (u treeUsage) exhausted() bool {
	return u.source >= maxTreeSource || u.function >= maxTreeFunctionWork ||
		u.locals >= maxTreeLocals || u.resources >= maxTreeResources || u.inputs >= maxTreeInputs || u.outputs >= maxTreeOutputs ||
		u.refs >= maxTreeReferences || u.unknown >= maxTreeUnknownSteps ||
		u.expansion >= maxTreeExpansionWork || u.structure >= maxTreeStructure || u.instances >= maxTreeInstances
}

// usageOf returns what m has used so far, apart from its source. Its calls' expansion work
// counts as expansion work, and its attributes' reference entries as reference entries.
func usageOf(m *ParsedModule) treeUsage {
	u := m.usage
	u.expansion += u.callExpansion
	u.callExpansion = 0
	u.refs += m.attrRefs // the reference entries of attributes, outputs and module inputs
	return treeUsage{function: m.fnWork, moduleUsage: u}
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
	// Address is "" for the root, else the instance's address: the caller's, then
	// "module.<name>" and its key ("module.a[0].module.b[\"k\"]"), or "[*]" for the placeholder
	// of an unknown or invalid count or for_each. Dir is the module directory.
	Address, Dir string
	// Key is the instance's count index or for_each key; NoKey without count or for_each and
	// for a placeholder, which sets ExpansionUnknown.
	Key              model.InstanceKey
	ExpansionUnknown bool
	// Call is the module call, nil for the root.
	Call *ModuleCall
	// Module is the instance, which holds its evaluation diagnostics; parse diagnostics stay on
	// the tree's parse.
	Module *ParsedModule
	// Skipped reports that the tree's budget was used up before this instance: nothing in it
	// was evaluated, and its calls are not listed.
	Skipped bool
	// Truncated reports that the instance's calls used up the tree's budget: its variables,
	// locals and calls were evaluated, its resources and outputs were not.
	Truncated bool
	Variables map[string]Variable
	Locals    map[string]Local
	// Resources carry the instance's address in Module and as their address prefix.
	Resources []Resource
	// Outputs are the instance's outputs, which its caller sees as module.<name>.
	Outputs map[string]Output
	// Providers are the instance's provider blocks.
	Providers []ProviderConfig
}

// treeEvaluator evaluates one ModuleTree.
type treeEvaluator struct {
	// rootDir is the root module's directory.
	rootDir string
	// instances counts the module instances started (the root is not one), at most
	// maxTreeModuleInstances.
	instances int
	root      *fsutil.Root
	opts      VarOptions
	limits    Limits
	used      treeUsage
	charged   map[*ParsedModule]treeUsage
	out       []*ModuleInstance
}

// EvaluateTree evaluates every resolved module of tree, depth first, in the dependency order of
// each module's locals and calls: the root
// with its variables from defaults, tfvars and opts (EvaluateVariables), each child with its
// variables from its call's inputs evaluated in the caller (ModuleInputs), each in its own
// instance with its locals, resources and outputs. A module's locals and calls are evaluated in
// one dependency order, and its locals, module inputs, resources and outputs see its calls'
// outputs as module.<name>. Instances are listed in the order they start. Once
// the tree's budgets are used up, the remaining instances are Skipped, and child instances
// whose calls used them up are Truncated (ADR 0010), each with a module_work_limit warning at
// its call. Unresolved calls have no instance. Problems in the files are diagnostics; a file
// that cannot be read or a cancelled context is an error.
func EvaluateTree(ctx context.Context, root *fsutil.Root, tree *ModuleTree, opts VarOptions, limits Limits) ([]*ModuleInstance, error) {
	e := &treeEvaluator{root: root, opts: opts, limits: limits, charged: map[*ParsedModule]treeUsage{}, rootDir: tree.Root.Dir}
	if _, err := e.evaluate(ctx, tree.Root, nil, nil, instanceSpec{}, nil); err != nil {
		return nil, fmt.Errorf("evaluate module tree: %w", err)
	}
	return e.out, nil
}

// evaluate evaluates node, loaded by call from caller (both nil for the root), whose inputs
// gives its call's arguments evaluated in the caller: its variables, then its locals and calls
// in one dependency order (T-0107i), then its resources and outputs, which see the calls'
// outputs.
func (e *treeEvaluator) evaluate(ctx context.Context, node *ModuleNode, call *ModuleCall, caller *ModuleInstance, spec instanceSpec, inputs func() (map[string]Input, error)) (*ModuleInstance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inst := &ModuleInstance{Dir: node.Dir, Call: call, Module: node.Module.NewInstance(), Key: spec.key}
	if caller != nil {
		inst.Address = "module." + call.Name + spec.suffix
		if caller.Address != "" {
			inst.Address = caller.Address + "." + inst.Address
		}
		inst.ExpansionUnknown = spec.suffix == "[*]"
		e.instances++
		// Paths resolve against the root module's directory, and path.module locates this
		// module from there (T-0107f).
		inst.Module.baseDir, inst.Module.pathModule = e.rootDir, pathFrom(e.rootDir, node.Dir)
		inst.Module.addrPrefix = inst.Address
	}
	e.out = append(e.out, inst)
	m := inst.Module
	if caller != nil && e.used.exhausted() {
		inst.Skipped = true
		r := call.DefRange
		caller.Module.diag(SeverityWarning, DiagModuleWorkLimit, "Module tree too large to evaluate",
			"The module tree used up its evaluation budget, so this module instance and the modules it calls are not checked.",
			call.File, r.Start.Line, r.Start.Column)
		caller.Module.sortDiagnostics()
		return inst, nil
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
		var in map[string]Input
		if in, err = inputs(); err == nil {
			inst.Variables, err = m.EvaluateModuleVariables(ctx, call, in)
		}
	}
	if err != nil {
		return nil, err
	}

	evalCall := func(c *ModuleCall, locals map[string]Local, modules map[string]cty.Value) (cty.Value, error) {
		if c.Child == nil {
			return cty.DynamicVal, nil
		}
		return e.evaluateCall(ctx, inst, c, locals, modules)
	}
	// A child stops evaluating locals once the tree budget is used up (ADR 0011); the root
	// never does.
	var stop func() bool
	if caller != nil {
		stop = func() bool {
			e.charge(m)
			return e.used.exhausted()
		}
	}
	var modules map[string]cty.Value
	if inst.Locals, modules, err = m.evaluateLocals(ctx, inst.Variables, node.Calls, evalCall, stop); err != nil {
		return nil, err
	}
	e.charge(m)

	// The calls may have used up the tree's budget after this instance started: then its
	// resources and outputs are not evaluated (ADR 0010). The root is always evaluated.
	if caller != nil && e.used.exhausted() {
		inst.Truncated = true
		r := call.DefRange
		caller.Module.diag(SeverityWarning, DiagModuleWorkLimit, "Module tree too large to evaluate",
			"The modules this module instance calls used up the module tree's evaluation budget, so its resources and outputs are not checked.",
			call.File, r.Start.Line, r.Start.Column)
		caller.Module.sortDiagnostics()
		return inst, nil
	}
	if inst.Resources, err = m.decodeResources(ctx, inst.Variables, inst.Locals, modules); err != nil {
		return nil, err
	}
	if call != nil {
		for i := range inst.Resources {
			r := &inst.Resources[i]
			r.Module, r.CallFile, r.CallRange = inst.Address, call.File, call.DefRange
			r.Address = inst.Address + "." + r.Address
			r.BaseAddress = inst.Address + "." + r.BaseAddress
		}
	}
	inst.Providers = m.ProviderConfigs()
	if inst.Outputs, err = m.evaluateOutputs(ctx, inst.Variables, inst.Locals, modules); err != nil {
		return nil, err
	}
	e.charge(m)
	return inst, nil
}

// evaluateCall evaluates the instances of call c of caller: one per count index or for_each key
// (expanded as for resources, at most maxInstancesPerResource), one placeholder for an unknown
// or invalid expansion, or one without count or for_each. It returns module.<name> for the
// caller: an object of the outputs, a tuple of them by index (count), an object of them by key
// (for_each), or unknown for a placeholder, an expansion cut at a limit, or an instance that was
// skipped or truncated.
func (e *treeEvaluator) evaluateCall(ctx context.Context, caller *ModuleInstance, c *ModuleCall, locals map[string]Local, modules map[string]cty.Value) (cty.Value, error) {
	m := caller.Module
	attrs, _ := c.Body.JustAttributes() // moduleInputs reports these diagnostics
	r := Resource{DefRange: c.DefRange}
	if a, ok := attrs["count"]; ok {
		r.Count = a.Expr
	}
	if a, ok := attrs["for_each"]; ok {
		r.ForEach = a.Expr
	}
	d, done := m.callDecoder(caller.Variables, locals, modules)
	specs := d.expand(&r)
	done()
	limited := d.instancesLimited

	// Each instance after the first evaluates the call's arguments again: their source is
	// charged to the caller's expansion work, as a resource body is (maxExpansionWork).
	cost := 1
	for name, a := range attrs {
		if moduleMetaArguments[name] {
			continue
		}
		ar := a.Expr.Range()
		n := ar.End.Byte - ar.Start.Byte
		if strings.HasSuffix(ar.Filename, ".json") {
			n *= jsonEvalFactor
		}
		cost += n
	}

	outputs := make([]cty.Value, 0, len(specs))
	for i, spec := range specs {
		if i > 0 && m.usage.callExpansion+cost > maxExpansionWork {
			limited = true
			at := c.DefRange
			m.diag(SeverityWarning, DiagExpansionLimit, "Too many module instances",
				"The module call's arguments, evaluated again for each instance, pass the limit for a module, so the rest of its instances are not checked.",
				c.File, at.Start.Line, at.Start.Column)
			m.sortDiagnostics()
			break
		}
		if i > 0 {
			m.usage.callExpansion += cost
		}
		if e.instances >= maxTreeModuleInstances {
			limited = true
			at := c.DefRange
			m.diag(SeverityWarning, DiagExpansionLimit, "Too many module instances",
				fmt.Sprintf("The module tree has %d module instances, so the rest of this module call's instances are not checked.", maxTreeModuleInstances),
				c.File, at.Start.Line, at.Start.Column)
			m.sortDiagnostics()
			break
		}
		e.charge(m) // the caller's work so far, before the child checks the budget
		child, err := e.evaluate(ctx, c.Child, c, caller, spec, func() (map[string]Input, error) {
			in, err := m.moduleInputs(ctx, c, caller.Variables, locals, modules, spec.vars)
			e.charge(m)
			return in, err
		})
		if err != nil {
			return cty.DynamicVal, err
		}
		v := cty.DynamicVal
		if !child.Skipped && !child.Truncated {
			v = outputsObject(child.Outputs)
		}
		outputs = append(outputs, v)
	}
	switch {
	case r.CountUnknown || r.ForEachUnknown || limited:
		return cty.DynamicVal, nil
	case r.Count != nil:
		return cty.TupleVal(outputs), nil
	case r.ForEach != nil:
		byKey := make(map[string]cty.Value, len(specs))
		for i, spec := range specs {
			k, _ := spec.key.Str()
			byKey[k] = outputs[i]
		}
		return cty.ObjectVal(byKey), nil
	case len(outputs) == 0:
		return cty.DynamicVal, nil // the tree was already full
	default:
		return outputs[0], nil
	}
}

// charge adds what m used since it was last charged to the tree.
func (e *treeEvaluator) charge(m *ParsedModule) {
	now, before := usageOf(m), e.charged[m]
	u := &e.used
	u.function += now.function - before.function
	u.locals += now.locals - before.locals
	u.resources += now.resources - before.resources
	u.inputs += now.inputs - before.inputs
	u.outputs += now.outputs - before.outputs
	u.refs += now.refs - before.refs
	u.unknown += now.unknown - before.unknown
	u.expansion += now.expansion - before.expansion
	u.structure += now.structure - before.structure
	u.instances += now.instances - before.instances
	e.charged[m] = now
}

// pathFrom returns target relative to base, both slash-separated and relative to the scan
// root, as Terraform writes path.module: "modules/net", "../shared" or ".".
func pathFrom(base, target string) string {
	rel, err := filepath.Rel(filepath.FromSlash(base), filepath.FromSlash(target))
	if err != nil {
		return target // both are relative to one root, so Rel cannot fail
	}
	return filepath.ToSlash(rel)
}
