package terraform

import (
	"context"
	"slices"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// DiagUninstantiatedModule reports a local module that no root module instantiates, which is
// scanned on its own as a root.
const DiagUninstantiatedModule DiagCode = "uninstantiated_module"

// RootResult is one evaluated root module.
type RootResult struct {
	Dir string
	// Orphan reports a local child that no root instantiated (its calls are absent, have
	// count = 0 or an empty for_each, or come only from an override file): it is scanned on
	// its own, as a root with only its own defaults and tfvars, and warned about.
	Orphan    bool
	Tree      *ModuleTree
	Instances []*ModuleInstance
	// ProviderVersions are the exact provider versions of the root's .terraform.lock.hcl, by
	// source address (ReadLockFile); its warnings are on the root instance.
	ProviderVersions map[string]string
}

// EvaluateRoots loads and evaluates every root module of mods, in order, then scans as roots
// the local children that no evaluated tree instantiated, so that no local module is skipped
// silently (T-0107e). The children are those of mods and every directory a loaded tree reaches
// through a resolved call, even one with count = 0 (hidden modules are not classified, but their
// calls are loaded). A child with an instance in some tree, even one skipped for the tree's
// budget, is covered: skipped instances are reported at their call. Orphans are promoted in
// rounds: an orphan called by another orphan waits, since evaluating its caller may instantiate
// it; when all wait, the first orphan by path that is in a cycle of orphans goes first. opts (the
// pipeline's variables) apply to mods.Roots only, and orphans never trust the module manifest:
// the pipeline prepared .terraform for its roots only (ADR 0014). Problems in the files are
// diagnostics; a file that cannot be read or a cancelled context is an error.
func EvaluateRoots(ctx context.Context, root *fsutil.Root, d *Discovery, mods *Modules, opts VarOptions, limits Limits, topts TreeOptions) ([]RootResult, error) {
	var out []RootResult
	covered := map[string]bool{}
	children := map[string]bool{}
	callers := map[string]map[string]bool{}
	addCaller := func(child, caller string) {
		children[child] = true
		if callers[child] == nil {
			callers[child] = map[string]bool{}
		}
		callers[child][caller] = true
	}
	for _, child := range mods.Children {
		for _, caller := range mods.CalledBy[child] {
			addCaller(child, caller)
		}
		children[child] = true
	}
	var walk func(n *ModuleNode)
	walk = func(n *ModuleNode) {
		for _, c := range n.Calls {
			if c.Child != nil {
				addCaller(c.Child.Dir, n.Dir)
				walk(c.Child)
			}
		}
	}
	evaluate := func(dir string, orphan bool) error {
		to, vo := topts, opts
		if orphan {
			to, vo = TreeOptions{allowUndiscovered: true}, VarOptions{}
		}
		tree, err := LoadModuleTree(ctx, root, d, dir, limits, to)
		if err != nil {
			return err
		}
		walk(tree.Root)
		instances, err := EvaluateTree(ctx, root, tree, vo, limits)
		if err != nil {
			return err
		}
		if orphan {
			m := instances[0].Module
			m.diag(SeverityWarning, DiagUninstantiatedModule, "Module scanned on its own",
				"No root module instantiates this local module (its module calls are absent, have count = 0 or an empty for_each, or come from an override file), so it is scanned as a root, with unknown values for variables that have no default.",
				dir, 0, 0)
			m.sortDiagnostics()
		}
		for _, inst := range instances {
			covered[inst.Dir] = true
		}
		versions, diags := ReadLockFile(root, dir)
		if len(diags) > 0 {
			m := instances[0].Module
			m.Diagnostics = append(m.Diagnostics, diags...)
			m.sortDiagnostics()
		}
		out = append(out, RootResult{Dir: dir, Orphan: orphan, Tree: tree, Instances: instances, ProviderVersions: versions})
		return nil
	}
	for _, dir := range mods.Roots {
		if err := evaluate(dir, false); err != nil {
			return nil, err
		}
	}
	for {
		var orphans []string
		for child := range children {
			if !covered[child] {
				orphans = append(orphans, child)
			}
		}
		if len(orphans) == 0 {
			return out, nil
		}
		slices.SortFunc(orphans, comparePaths)
		isOrphan := make(map[string]bool, len(orphans))
		for _, o := range orphans {
			isOrphan[o] = true
		}
		// An orphan called by another orphan may be instantiated through it.
		next := slices.DeleteFunc(slices.Clone(orphans), func(dir string) bool {
			for caller := range callers[dir] {
				if caller != dir && isOrphan[caller] {
					return true
				}
			}
			return false
		})
		if len(next) == 0 {
			next = []string{firstInCycle(orphans, isOrphan, callers)}
		}
		for _, dir := range next {
			if err := evaluate(dir, true); err != nil {
				return nil, err
			}
		}
	}
}

// firstInCycle returns the first orphan, by path, that reaches itself through orphan callers.
// Every orphan waits on an orphan caller, so following callers from any orphan ends in a
// cycle; one exists.
func firstInCycle(orphans []string, isOrphan map[string]bool, callers map[string]map[string]bool) string {
	for _, start := range orphans {
		seen := map[string]bool{}
		stack := []string{start}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for caller := range callers[n] {
				if caller == start {
					return start
				}
				if isOrphan[caller] && !seen[caller] {
					seen[caller] = true
					stack = append(stack, caller)
				}
			}
		}
	}
	return orphans[0]
}
