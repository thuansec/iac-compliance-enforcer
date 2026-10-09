package terraform

import (
	"fmt"
	"os"
	"path/filepath"
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
			locals: maxTreeLocals - 1, resources: maxTreeResources - 1, inputs: maxTreeInputs - 1,
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
		locals: 1, resources: 2, inputs: 3, refs: 4, unknown: 5, expansion: 6, structure: 7, instances: 8,
	}}
	e.charge(m)
	m.fnWork, m.usage.inputs = 15, 9
	e.charge(m)
	e.charge(m)
	want := treeUsage{function: 15, moduleUsage: moduleUsage{
		locals: 1, resources: 2, inputs: 9, refs: 4, unknown: 5, expansion: 6, structure: 7, instances: 8,
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
