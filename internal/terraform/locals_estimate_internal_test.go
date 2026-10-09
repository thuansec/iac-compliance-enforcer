package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// The locals size estimate charges a traversal with static steps (local.cfg.env) the sub-value
// it reaches, not the whole value: six reads of one field of a 45 KB map were a false
// value_too_large (T-0104c review). Dynamic index steps and splats still charge the whole
// value, so the estimate stays an upper bound (T-0114).
func TestLocalsEstimateChargesTheUsedPart(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", 45_000)
	six := func(ref string) string {
		return `"` + strings.Repeat("${"+ref+"}-", 6) + `"`
	}
	for name, tc := range map[string]struct {
		expr    string
		refused bool
	}{
		"attribute steps": {six("local.cfg.env"), false},
		"literal index":   {six(`local.cfg["env"]`), false},
		"list index":      {six("local.list[0].env"), false},
		"variable steps":  {six("var.cfg.env"), false},
		"legacy step":     {six("local.list.0.env"), false},
		"sensitive base":  {six("var.secret.env"), false},
		"unknown midway":  {six("local.later.env"), false},
		"dynamic index":   {six("local.cfg[local.key]"), true},
		"splat":           {six("local.list[*].env[0]"), true},
		"whole value":     {`[` + strings.Repeat("local.cfg, ", 6) + `]`, true},
		"large element":   {`[` + strings.Repeat("local.list[0], ", 6) + `]`, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := parseLocalsModule(t, `locals {
  key  = "env"
  cfg  = { env = "prod", blob = "`+big+`" }
  list = [{ env = "a", blob = "`+big+`" }]
  later = { env = aws_s3_bucket.b.id, blob = "`+big+`" }
  v    = `+tc.expr+`
}
`)
			cfg := cty.ObjectVal(map[string]cty.Value{"env": cty.StringVal("prod"), "blob": cty.StringVal(big)})
			vars := map[string]Variable{
				"cfg":    {Name: "cfg", Value: cfg},
				"secret": {Name: "secret", Value: cfg.Mark(SensitiveMark)},
			}
			locals, err := m.EvaluateLocals(context.Background(), vars)
			if err != nil {
				t.Fatal(err)
			}
			refused := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagValueTooLarge })
			if refused != tc.refused {
				t.Errorf("refused %v, want %v: value %#v, diagnostics %v", refused, tc.refused, locals["v"].Value, m.Diagnostics)
			}
			if !tc.refused && name != "unknown midway" && !locals["v"].Value.IsWhollyKnown() {
				t.Errorf("value %#v, want it known", locals["v"].Value)
			}
		})
	}
}

// Measuring paths is charged to the module's function work, so paths that reach the same large
// value by different text (l["0"], l["00"], l["0e1"], ...) cannot walk it without bound: 3,000
// such locals took 80 s when only the text was cached (T-0114 review). Once the work is spent,
// the whole value's size is charged without walking, which stays an upper bound.
func TestPathMeasuringIsCharged(t *testing.T) {
	t.Parallel()
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, 120_000))
	m := &ParsedModule{}
	b := &localsBudget{
		m:        m,
		vars:     cty.ObjectVal(map[string]cty.Value{"c": cty.ObjectVal(map[string]cty.Value{"l": cty.TupleVal([]cty.Value{list})})}),
		sizes:    map[string]int{},
		varSizes: map[string]int{},
	}
	listSize, _ := valueSize(list, maxLocalValueSize, maxNesting)
	whole := b.size("var.c")
	for i := range 3000 {
		key := cty.StringVal(fmt.Sprintf("0e%d", i))
		n := b.pathSize(usePath{key: "var.c", steps: hcl.Traversal{hcl.TraverseAttr{Name: "l"}, hcl.TraverseIndex{Key: key}}}, nil)
		if n != listSize && n != whole {
			t.Fatalf("path %d: size %d, want the sub-value's %d or the whole value's %d", i, n, listSize, whole)
		}
	}
	if m.fnWork > maxFunctionWork {
		t.Errorf("charged %d, over the module's function work %d", m.fnWork, maxFunctionWork)
	}
	if want := maxFunctionWork / listSize; len(b.pathSizes) > want+1 {
		t.Errorf("%d paths measured, want at most %d: the work should have run out", len(b.pathSizes), want+1)
	}
}

// pathSize measures a path into a value that is set once, and keeps paths into locals not yet
// evaluated out of the cache.
func TestPathSizeIsCached(t *testing.T) {
	t.Parallel()
	b := &localsBudget{
		m:        &ParsedModule{},
		vars:     cty.ObjectVal(map[string]cty.Value{"c": cty.ObjectVal(map[string]cty.Value{"l": cty.ListVal([]cty.Value{cty.True, cty.False})})}),
		sizes:    map[string]int{},
		varSizes: map[string]int{},
	}
	steps := hcl.Traversal{hcl.TraverseAttr{Name: "l"}}
	if n := b.pathSize(usePath{key: "var.c", steps: steps}, nil); n != 3 || len(b.pathSizes) != 1 {
		t.Errorf("size %d, %d cached; want 3, 1", n, len(b.pathSizes))
	}
	b.vars = cty.EmptyObjectVal // a cached size is not measured again
	if n := b.pathSize(usePath{key: "var.c", steps: steps}, nil); n != 3 {
		t.Errorf("size %d after the cache, want 3", n)
	}
	b.pathSize(usePath{key: "local.later", steps: steps}, map[string]Local{})
	if len(b.pathSizes) != 1 {
		t.Errorf("%d cached; a path into a local not evaluated yet must not be cached", len(b.pathSizes))
	}
}

// A path into a module call's outputs is charged the sub-value too: six reads of one field of a
// module output holding 45 KB are not too large.
func TestLocalsEstimateChargesModulePaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, src := range map[string]string{
		"main.tf": "module \"c\" {\n  source = \"./c\"\n}\nlocals {\n  v = \"" +
			strings.Repeat("${module.c.out.env}-", 6) + "\"\n}\n",
		"c/main.tf": "output \"out\" {\n  value = { env = \"prod\", blob = \"" + strings.Repeat("x", 45_000) + "\" }\n}\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
	root := results[0].Instances[0]
	if v := root.Locals["v"].Value; !v.RawEquals(cty.StringVal(strings.Repeat("prod-", 6))) {
		t.Errorf("v = %#v, diagnostics %v; want it evaluated", v, root.Module.Diagnostics)
	}
}
