package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// bigListVars is var.c with c.l a 120,000-element list.
func bigListVars() map[string]Variable {
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, 120_000))
	return map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{"l": list})}}
}

// walkLimit is the most evaluations of an expression over the 120,000-element list that the
// module's function work pays for.
var walkLimit = maxFunctionWork/(argumentWalkWork*120_000) + 1

// Resource attributes walk their inputs in cty like locals, once per instance: 300 resources,
// or one with count = 300, each `length(var.c.l)` took about 20 s (T-0114a review). Each
// evaluation is now charged first, so the module's function work bounds them (T-0114b).
func TestResourceWalksAreCharged(t *testing.T) {
	t.Parallel()
	var many strings.Builder
	for i := range 300 {
		fmt.Fprintf(&many, "resource \"aws_s3_bucket\" \"b%d\" {\n  n = length(var.c.l)\n}\n", i)
	}
	count := func(expr string) string {
		return "resource \"aws_s3_bucket\" \"b\" {\n  count = 300\n  n     = " + expr + "\n}\n"
	}
	for name, src := range map[string]string{
		"resources": many.String(),
		"count":     count("length(var.c.l)"),
		// hcl also evaluates var["c"] and a bare var, which reach every variable (ADR 0027).
		"index call":     count(`length(var["c"].l)`),
		"index operator": count(`var["c"] != null`),
		"bare var":       count("var != null"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := parseFilesModule(t, map[string]string{"main.tf": src})
			res, err := m.DecodeResources(context.Background(), bigListVars(), map[string]Local{})
			if err != nil {
				t.Fatal(err)
			}
			known := 0
			for _, r := range res {
				if v := r.Value.GetAttr("n"); v.IsKnown() {
					known++
				}
			}
			if known == 0 || known > walkLimit || len(res) != 300 {
				t.Errorf("%d of %d resources evaluated n, want 1 to %d of 300", known, len(res), walkLimit)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
				t.Error("no function_limit diagnostic")
			}
		})
	}
}

// Outputs are evaluated through the same path and charged the same way.
func TestOutputWalksAreCharged(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 300 {
		fmt.Fprintf(&b, "output \"o%d\" {\n  value = length(var.c.l)\n}\n", i)
	}
	m := parseFilesModule(t, map[string]string{"main.tf": b.String()})
	outs, err := m.evaluateOutputs(context.Background(), bigListVars(), map[string]Local{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	known := 0
	for _, o := range outs {
		if o.Value.IsKnown() {
			known++
		}
	}
	if known == 0 || known > walkLimit {
		t.Errorf("%d of 300 outputs evaluated, want 1 to %d", known, walkLimit)
	}
	if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
		t.Error("no function_limit diagnostic")
	}
}

// Module inputs are evaluated through the same path, once per instance of the call, and charged
// the same way. An operator's walk is otherwise free, so without the charge all 300 evaluate.
func TestModuleInputWalksAreCharged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"main.tf":   "locals {\n  big = flatten([for i in range(30) : range(1000)])\n}\nmodule \"c\" {\n  source = \"./c\"\n  count  = 300\n  v      = local.big != null\n}\n",
		"c/main.tf": "variable \"v\" {}\n",
	})
	results := evaluateRootsIn(t, dir)
	known, children := 0, 0
	for _, inst := range results[0].Instances {
		if inst.Address == "" {
			continue
		}
		children++
		if v := inst.Variables["v"].Value; v.IsKnown() {
			known++
		}
	}
	// The input is a 30,000-element list (range is capped at 1,024, and one call at the
	// function value size).
	if limit := maxFunctionWork/(argumentWalkWork*30_000) + 1; children != 300 || known == 0 || known > limit {
		t.Errorf("%d of %d child instances got v, want 1 to %d of 300: %v", known, children, limit, results[0].Instances[0].Module.Diagnostics)
	}
	if !slices.ContainsFunc(results[0].Instances[0].Module.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
		t.Error("no function_limit diagnostic on the caller")
	}
}

// writeFiles writes files, relative paths to contents, under dir.
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// evaluateRootsIn discovers, classifies and evaluates the root modules in dir.
func evaluateRootsIn(t *testing.T, dir string) []RootResult {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	ctx := context.Background()
	limits := DefaultLimits()
	d, err := Discover(ctx, r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := ClassifyModules(ctx, r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	results, err := EvaluateRoots(ctx, r, d, mods, VarOptions{}, limits, TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return results
}

// A bare var reaches every variable, a sensitive one included, so a value it leaves unknown
// over the limit stays sensitive (fail closed), in locals and in resources.
func TestBareVarLimitStaysSensitive(t *testing.T) {
	t.Parallel()
	vars := bigListVars()
	vars["s"] = Variable{Name: "s", Value: cty.StringVal("FAKE-secret").Mark(SensitiveMark)}
	var b strings.Builder
	b.WriteString("locals {\n")
	for i := range 300 {
		fmt.Fprintf(&b, "  a%d = var != null\n", i)
	}
	b.WriteString("}\nresource \"aws_s3_bucket\" \"b\" {\n  count = 300\n  n     = var != null\n}\n")
	m := parseFilesModule(t, map[string]string{"main.tf": b.String()})
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	unknown := 0
	for name, l := range locals {
		if !l.Value.IsKnown() {
			unknown++
			if !l.Value.HasMark(SensitiveMark) {
				t.Errorf("local %s is unknown without the sensitive mark", name)
			}
		}
	}
	res, err := m.DecodeResources(context.Background(), vars, map[string]Local{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if n := r.Value.GetAttr("n"); !n.IsKnown() {
			unknown++
			if !n.HasMark(SensitiveMark) {
				t.Errorf("%s n is unknown without the sensitive mark", r.Address)
			}
		}
	}
	if unknown == 0 {
		t.Error("nothing reached the limit")
	}
}
