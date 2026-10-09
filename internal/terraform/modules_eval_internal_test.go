package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

func TestTreeUsageExhausted(t *testing.T) {
	t.Parallel()
	if (treeUsage{}).exhausted() {
		t.Error("an empty tree is exhausted")
	}
	below := treeUsage{
		source: maxTreeSource - 1, function: maxTreeFunctionWork - 1,
		moduleUsage: moduleUsage{
			locals: maxTreeLocals - 1, resources: maxTreeResources - 1, inputs: maxTreeInputs - 1, outputs: maxTreeOutputs - 1,
			refs: maxTreeReferences - 1, unknown: maxTreeUnknownSteps - 1,
			expansion: maxTreeExpansionWork - 1, structure: maxTreeStructure - 1, instances: maxTreeInstances - 1,
		},
	}
	if below.exhausted() {
		t.Error("a tree just below every budget is exhausted")
	}
	for name, set := range map[string]func(*treeUsage){
		"source":    func(u *treeUsage) { u.source = maxTreeSource },
		"function":  func(u *treeUsage) { u.function = maxTreeFunctionWork },
		"locals":    func(u *treeUsage) { u.locals = maxTreeLocals },
		"resources": func(u *treeUsage) { u.resources = maxTreeResources },
		"inputs":    func(u *treeUsage) { u.inputs = maxTreeInputs },
		"outputs":   func(u *treeUsage) { u.outputs = maxTreeOutputs },
		"refs":      func(u *treeUsage) { u.refs = maxTreeReferences },
		"unknown":   func(u *treeUsage) { u.unknown = maxTreeUnknownSteps },
		"expansion": func(u *treeUsage) { u.expansion = maxTreeExpansionWork },
		"structure": func(u *treeUsage) { u.structure = maxTreeStructure },
		"instances": func(u *treeUsage) { u.instances = maxTreeInstances },
	} {
		u := below
		set(&u)
		if !u.exhausted() {
			t.Errorf("%s at its budget is not exhausted", name)
		}
	}
}

// charge adds only what a module used since its last charge, so charging a caller after each of
// its calls' inputs never counts its own evaluation twice.
func TestChargeAddsDeltas(t *testing.T) {
	t.Parallel()
	e := &treeEvaluator{charged: map[*ParsedModule]treeUsage{}}
	m := &ParsedModule{fnWork: 10, usage: moduleUsage{
		locals: 1, resources: 2, inputs: 3, outputs: 10, refs: 4, unknown: 5, expansion: 6, structure: 7, instances: 8,
	}}
	e.charge(m)
	m.fnWork, m.usage.inputs = 15, 9
	e.charge(m)
	e.charge(m)
	want := treeUsage{function: 15, moduleUsage: moduleUsage{
		locals: 1, resources: 2, inputs: 9, outputs: 10, refs: 4, unknown: 5, expansion: 6, structure: 7, instances: 8,
	}}
	if e.used != want {
		t.Errorf("used = %+v, want %+v", e.used, want)
	}
}

// Evaluating locals and resources records what they used, for the tree to charge.
func TestEvaluationRecordsUsage(t *testing.T) {
	t.Parallel()
	m := parseLocalsModule(t, `locals {
  name = "abcdef"
  id   = aws_vpc.v.id
  both = [local.name, local.id]
}
resource "aws_s3_bucket" "b" {
  count  = 3
  bucket = local.name
  vpc    = aws_vpc.v.id
}
`)
	locals, err := m.EvaluateLocals(t.Context(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.DecodeResources(t.Context(), map[string]Variable{}, locals); err != nil {
		t.Fatal(err)
	}
	u := m.usage
	// Unknown paths: local.id (1 path, 0 steps), local.both[1] (1 path, 1 step), and each
	// bucket's vpc (3 paths, 1 step each).
	if u.locals == 0 || u.refs == 0 || u.unknown != 1+2+3*2 || u.resources == 0 ||
		u.expansion == 0 || u.structure == 0 || u.instances != 3 {
		t.Errorf("usage = %+v", u)
	}
	if got := usageOf(m); got.moduleUsage != u {
		t.Errorf("usageOf = %+v", got)
	}
}

func TestPathSteps(t *testing.T) {
	t.Parallel()
	paths := []cty.Path{{}, cty.GetAttrPath("a"), cty.GetAttrPath("a").IndexInt(0)}
	if got := pathSteps(paths); got != 3+0+1+2 {
		t.Errorf("pathSteps = %d, want 6", got)
	}
}

// evaluateFanOut evaluates a root calling child 1,000 times.
func evaluateFanOut(t *testing.T, child string) []*ModuleInstance {
	t.Helper()
	dir := t.TempDir()
	var root strings.Builder
	for i := range MaxModuleCalls {
		fmt.Fprintf(&root, "module \"c%d\" {\n  source = \"./c\"\n}\n", i)
	}
	if err := os.MkdirAll(filepath.Join(dir, "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"main.tf": root.String(), "c/main.tf": child} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := Discover(t.Context(), r, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := LoadModuleTree(t.Context(), r, d, ".", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	instances, err := EvaluateTree(t.Context(), r, tree, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return instances
}

// treeTotals sums the reference entries and unknown path steps of the evaluated instances, and
// returns the largest single instance's amounts.
func treeTotals(instances []*ModuleInstance) (refs, unknown, maxRefs, maxUnknown, evaluated int) {
	for _, inst := range instances {
		if inst.Skipped {
			continue
		}
		evaluated++
		r, u := 0, 0
		for _, l := range inst.Locals {
			r += len(l.References)
			u += pathSteps(l.Unknown)
		}
		for _, res := range inst.Resources {
			u += pathSteps(res.Unknown)
		}
		refs, unknown = refs+r, unknown+u
		maxRefs, maxUnknown = max(maxRefs, r), max(maxUnknown, u)
	}
	return refs, unknown, maxRefs, maxUnknown, evaluated
}

// T-0107g review: chained locals store references quadratically, up to maxReferenceEntries per
// module; 1,000 small instances held 51.7M entries before the tree charged them.
func TestEvaluateTreeBoundsReferenceEntries(t *testing.T) {
	t.Parallel()
	var child strings.Builder
	child.WriteString("locals {\n  l0 = 0\n")
	for i := 1; i < 512; i++ {
		fmt.Fprintf(&child, "  l%d = length([local.l%d, aws_x.r%d])\n", i, i-1, i)
	}
	child.WriteString("}\n")
	refs, _, maxRefs, _, evaluated := treeTotals(evaluateFanOut(t, child.String()))
	if evaluated == MaxModuleCalls+1 || refs > maxTreeReferences+maxRefs {
		t.Errorf("%d instances evaluated with %d reference entries; want at most %d + %d",
			evaluated, refs, maxTreeReferences, maxRefs)
	}
}

// T-0107g review: unknown paths hold memory their value units do not count (3M paths took
// 385 MiB in one module); the tree charges their steps.
func TestEvaluateTreeBoundsUnknownPaths(t *testing.T) {
	t.Parallel()
	var child strings.Builder
	child.WriteString("locals {\n  l0 = [for i in range(1024) : aws_x.r.id]\n")
	for i := 1; i < 100; i++ {
		fmt.Fprintf(&child, "  l%d = local.l0\n", i)
	}
	child.WriteString("}\n")
	_, unknown, _, maxUnknown, evaluated := treeTotals(evaluateFanOut(t, child.String()))
	if evaluated == MaxModuleCalls+1 || unknown > maxTreeUnknownSteps+maxUnknown {
		t.Errorf("%d instances evaluated with %d unknown path steps; want at most %d + %d",
			evaluated, unknown, maxTreeUnknownSteps, maxUnknown)
	}
}

// Evaluating outputs records their value size and unknown path steps.
func TestOutputsRecordUsage(t *testing.T) {
	t.Parallel()
	m := parseLocalsModule(t, `output "a" {
  value = "abcdef"
}
output "b" {
  value = [aws_vpc.v.id]
}
`)
	outputs, err := m.evaluateOutputs(t.Context(), map[string]Variable{}, map[string]Local{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 2 || m.usage.outputs == 0 || m.usage.unknown != 2 {
		t.Errorf("%d outputs, usage %+v; want outputs above zero and 2 unknown steps", len(outputs), m.usage)
	}
}

// T-0107h review: with calls evaluated before resources, every ancestor on the call stack
// decoded its resources after the tree budget was used up (a chain of 30 resource-heavy modules
// used 29 times the budget). An ancestor whose calls used up the budget is Truncated, so each
// kind stays within the tree budget plus one instance's use plus the root's.
func TestEvaluateTreeBoundsAncestorsOfDeepChains(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("main.tf", "module \"m1\" {\n  source = \"./m1\"\n}\nresource \"aws_s3_bucket\" \"r\" {\n  o = module.m1.o\n}\n")
	const depth = 30
	for i := 1; i <= depth; i++ {
		var b strings.Builder
		fmt.Fprintf(&b, "variable \"big\" {\n  default = %q\n}\nresource \"aws_s3_bucket\" \"b\" {\n", strings.Repeat("x", 200_000))
		for j := range 25 {
			fmt.Fprintf(&b, "  a%d = upper(var.big)\n", j)
		}
		b.WriteString("}\noutput \"o\" {\n  value = \"x\"\n}\n")
		if i < depth {
			fmt.Fprintf(&b, "module \"m%d\" {\n  source = \"../m%d\"\n}\n", i+1, i+1)
		}
		write(fmt.Sprintf("m%d/main.tf", i), b.String())
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := Discover(t.Context(), r, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := LoadModuleTree(t.Context(), r, d, ".", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	instances, err := EvaluateTree(t.Context(), r, tree, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var fn, res, maxFn, maxRes, truncated int
	for _, inst := range instances {
		u := inst.Module.usage
		fn, res = fn+inst.Module.fnWork, res+u.resources
		maxFn, maxRes = max(maxFn, inst.Module.fnWork), max(maxRes, u.resources)
		if inst.Truncated {
			truncated++
			if inst.Resources != nil || inst.Outputs != nil {
				t.Errorf("%s is truncated but has resources or outputs", inst.Address)
			}
		}
	}
	// The root here is light, so one instance's use bounds both the overshoot and the root.
	if fn > maxTreeFunctionWork+2*maxFn || res > maxTreeResources+2*maxRes {
		t.Errorf("function work %d (budget %d, one module %d), resources %d (budget %d, one module %d)",
			fn, maxTreeFunctionWork, maxFn, res, maxTreeResources, maxRes)
	}
	if truncated == 0 {
		t.Error("no ancestor was truncated")
	}
	// Each truncated instance is reported at its call, on its caller.
	for i, inst := range instances {
		if !inst.Truncated {
			continue
		}
		caller := instances[i-1] // a chain: the previous instance is the caller
		line := inst.Call.DefRange.Start.Line
		if !slices.ContainsFunc(caller.Module.Diagnostics, func(d Diagnostic) bool {
			return d.Code == DiagModuleWorkLimit && d.File == inst.Call.File && d.Line == line
		}) {
			t.Errorf("%s is truncated without a module_work_limit warning at %s:%d", inst.Address, inst.Call.File, line)
		}
	}
	// The root sees a truncated child's outputs as unknown, without an evaluation warning.
	root := instances[0]
	if !instances[1].Truncated {
		t.Fatal("module.m1 is not truncated")
	}
	if v := root.Resources[0].Value.GetAttr("o"); v.IsKnown() {
		t.Errorf("module.m1.o = %#v, want unknown", v)
	}
	if slices.ContainsFunc(root.Module.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagEvaluation }) {
		t.Error("evaluation warning for a truncated module's output")
	}
}
