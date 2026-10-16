package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// hasDiagnostic reports whether m has a diagnostic with summary.
func hasDiagnostic(m *ParsedModule, summary string) bool {
	return slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == summary })
}

// hcl writes numbers as text itself in template parts beside literal text, in for expression
// and object constructor keys, and in map indexes: each such number is charged numberTextCost
// (T-0124b). An object for expression over 90 multiples of 1e-2466 took 198 ms, charged 8,377
// units.
func TestNumbersWrittenByExpressionsAreCharged(t *testing.T) {
	t.Parallel()
	n := numberAt(t, "123", 8_192) // 2.4 ms to write
	per := numberTextCost(n)
	vars := map[string]Variable{"n": {Name: "n", Value: n}}
	for _, tc := range []struct {
		expr  string
		times int
	}{
		{`"x${var.n}"`, 1},
		{`"${var.n}-${var.n}"`, 2},
		{`{for i in range(3) : "k${i}" => var.n}`, 0}, // values are not written
		{`{for i in range(3) : var.n + i => 1}`, 3},
		{`{(var.n) = 1}`, 1},
		{`{"123" = 1}[var.n]`, 1},
		{`format("%v", var.n)`, 1},
		{`formatlist("%v-%v", [var.n, var.n], var.n)`, 4}, // two elements, and the scalar per row
	} {
		m, v := evalLocal(t, tc.expr, vars)
		if !v.IsKnown() {
			t.Errorf("%s: unknown: %v", tc.expr, m.Diagnostics)
		}
		if m.fnWork < tc.times*per || tc.times == 0 && m.fnWork >= per {
			t.Errorf("%s: function work %d; want %d formats of %d", tc.expr, m.fnWork, tc.times, per)
		}
	}
	// A template that is one interpolation is that value, not text: nothing is written.
	if m, _ := evalLocal(t, `"${var.n}"`, vars); m.fnWork >= per {
		t.Errorf(`"${var.n}": function work %d; want no formatting charged`, m.fnWork)
	}
}

// Repeating a costly formatting stops at the module's work: 1,000 templates over a number at
// 8,192 bits took 2.4 s, charged about 1,000 units, and 90 keys of 1e-2466 multiples 198 ms.
// Over the limit the value is unknown with a warning, and keeps the marks of what it wrote.
func TestRepeatedNumberFormattingIsBounded(t *testing.T) { // not parallel: it measures time
	vars := map[string]Variable{
		"n": {Name: "n", Value: numberAt(t, "123", 8_192)},
		"s": {Name: "s", Value: numberAt(t, "123", 8_192).Mark(SensitiveMark)},
		"m": {Name: "m", Value: cty.ObjectVal(map[string]cty.Value{
			numberAt(t, "1e-150", 512).AsBigFloat().Text('f', -1): cty.NumberIntVal(1),
			"7": cty.NumberIntVal(1),
		})},
	}
	for _, expr := range []string{
		`[for i in range(1000) : "x${var.n}"]`,
		`[for i in range(1000) : {for j in range(3) : var.n + j => 1}]`,
		`[for i in range(1000) : format("%v", var.n)]`,
		`[for i in range(1000) : "x${var.s}"]`,
		// Literal keys below the refusal threshold are charged on every iteration (T-0124b
		// review: 5.2 s and 1.7 s uncharged).
		`[for i in range(1000) : [for j in range(100) : var.m[1e-150]]]`,
		`[for i in range(1000) : [for j in range(100) : var.m[7]]]`,
	} {
		start := time.Now()
		m, v := evalLocal(t, expr, vars)
		if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
			t.Errorf("%s: took %v", expr, elapsed)
		}
		if v.IsWhollyKnown() { // a refused call is an unknown element, a refused text the whole value
			t.Errorf("%s: wholly known; want unknown", expr)
		}
		if !hasDiagnostic(m, "Number formatting too large") && !hasDiagnostic(m, "Function call too large") &&
			!hasDiagnostic(m, "For expression too large") {
			t.Errorf("%s: diagnostics %v; want a limit warning", expr, m.Diagnostics)
		}
	}
	m, v := evalLocal(t, `{ a = "x${var.s}", b = [for i in range(1000) : "x${var.n}"] }`, vars)
	if v.IsKnown() || !v.HasMark(SensitiveMark) {
		t.Errorf("known %v, sensitive %v; want unknown and sensitive: %v", v.IsKnown(), v.HasMark(SensitiveMark), m.Diagnostics)
	}
	if m, v := evalLocal(t, `"x${var.s}"`, vars); !v.IsKnown() || !v.HasMark(SensitiveMark) {
		t.Errorf("accepted: known %v, sensitive %v; want known and sensitive: %v", v.IsKnown(), v.HasMark(SensitiveMark), m.Diagnostics)
	}
}

// hcl parses a literal index as a traversal step, which cannot be wrapped: an index whose
// number costs more than maxSetNumberFormatCost to write makes the expression unsafe, while
// ordinary indexes evaluate.
func TestCostlyLiteralIndexesAreRefused(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"m": {Name: "m", Value: cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1)})},
		"l": {Name: "l", Value: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})},
	}
	for expr, known := range map[string]bool{
		`var.m[1e-2466]`:                       false,
		`[for i in range(10) : var.m[1e-300]]`: false,
		`var.l[1]`:                             true,
		`var.l[0.5 * 2]`:                       true,
		`var.m["a"]`:                           true,
	} {
		m, v := evalLocal(t, expr, vars)
		if v.IsKnown() != known {
			t.Errorf("%s: known %v, want %v: %v", expr, v.IsKnown(), known, m.Diagnostics)
		}
		if !known && !hasDiagnostic(m, "Expression too complex") {
			t.Errorf("%s: diagnostics %v; want Expression too complex", expr, m.Diagnostics)
		}
	}
}

// The text wrapper takes a state capsule only the rewrite can create, so a configuration that
// calls it itself fails on that argument.
func TestHandWrittenTextWrapperFails(t *testing.T) {
	t.Parallel()
	m, v := evalLocal(t, `__iace_text(1, 2)`, nil)
	if v.IsKnown() || !hasDiagnostic(m, "Invalid function argument") {
		t.Errorf("value %#v, diagnostics %v; want unknown with an invalid argument", v, m.Diagnostics)
	}
}

// .tf.json templates are checked like HCL: a costly literal index makes the value unknown
// (T-0124b review: nested loops over var.m[1e-2466] in .tf.json took 25 s).
func TestCostlyLiteralIndexesInJSONAreRefused(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{"main.tf.json": `{"locals": {"v": "${var.m[1e-2466]}", "w": "${var.m[\"a\"]}"}}`})
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{
		"m": {Name: "m", Value: cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1)})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if locals["v"].Value.IsKnown() || !hasDiagnostic(m, "Expression too complex") {
		t.Errorf("v = %#v, diagnostics %v; want unknown and too complex", locals["v"].Value, m.Diagnostics)
	}
	if !locals["w"].Value.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("w = %#v; want 1", locals["w"].Value)
	}
}

// Outside for expressions an expression's literal numbers are written as text on every
// evaluation: one local of 10,000 uses of var.m[1e-150] (1,024 units each, under the refusal
// threshold) took 1.6 s uncharged (T-0124b review). It is charged before it is evaluated, so it
// is unknown with a warning, while a few such uses evaluate.
func TestLiteralTextOutsideLoopsIsCharged(t *testing.T) {
	t.Parallel()
	key := numberAt(t, "1e-150", 512).AsBigFloat().Text('f', -1)
	vars := map[string]Variable{"m": {Name: "m", Value: cty.ObjectVal(map[string]cty.Value{key: cty.NumberIntVal(1)})}}
	m, v := evalLocal(t, "["+strings.Repeat("var.m[1e-150], ", 10_000)+"]", vars)
	if v.IsKnown() || !hasDiagnostic(m, "Number formatting too large") {
		t.Errorf("known %v, diagnostics %v; want unknown with Number formatting too large", v.IsKnown(), m.Diagnostics)
	}
	if m.fnWork < maxFunctionWork/2 {
		t.Errorf("function work %d; want the refusal to spend its charge", m.fnWork)
	}
	m, v = evalLocal(t, "[var.m[1e-150], var.m[1e-150]]", vars)
	if !v.IsWhollyKnown() || m.fnWork < 2*numberTextCost(numberAt(t, "1e-150", 512)) {
		t.Errorf("value %#v, function work %d; want known and both uses charged", v, m.fnWork)
	}
	// The refusal happens before evaluation, so the unknown is marked from the local's inputs.
	vars["s"] = Variable{Name: "s", Value: cty.StringVal("FAKE").Mark(SensitiveMark)}
	m, v = evalLocal(t, "[var.s, "+strings.Repeat("var.m[1e-150], ", 10_000)+"]", vars)
	if v.IsKnown() || !v.HasMark(SensitiveMark) {
		t.Errorf("known %v, sensitive %v; want unknown and sensitive: %v", v.IsKnown(), v.HasMark(SensitiveMark), m.Diagnostics)
	}
	// .tf.json templates are charged the same way (T-0124b review).
	for uses, known := range map[int]bool{10_000: false, 2: true} {
		src := `{"locals": {"m": {"` + key + `": "a"}, "v": "` + strings.Repeat("${local.m[1e-150]}", uses) + `"}}`
		jm := parseFilesModule(t, map[string]string{"main.tf.json": src})
		locals, err := jm.EvaluateLocals(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := locals["v"].Value.IsKnown(); got != known || !known && !hasDiagnostic(jm, "Number formatting too large") {
			t.Errorf(".tf.json, %d uses: known %v, want %v: %v", uses, got, known, jm.Diagnostics)
		}
		if jm.fnWork < uses*numberTextCost(numberAt(t, "1e-150", 512)) && known {
			t.Errorf(".tf.json, %d uses: function work %d; want them charged", uses, jm.fnWork)
		}
		if !known && jm.fnWork < maxFunctionWork/2 {
			t.Errorf(".tf.json, %d uses: function work %d; want the refusal to spend its charge", uses, jm.fnWork)
		}
	}
}

// Resource attributes and module inputs are refused for their literal text like locals, and
// their unknown keeps the marks of the inputs they use: evalExpr's unknown carries none, so
// resourceDecoder.evalBounded returns its own (textRefused, T-0124b review). The local drain
// spends the module's function work first: one attribute of 10,000 uses would pass the size
// limit for an attribute before its text is charged.
func TestRefusedLiteralTextKeepsInputMarks(t *testing.T) {
	t.Parallel()
	key := numberAt(t, "1e-150", 512).AsBigFloat().Text('f', -1)
	uses := strings.Repeat("var.m[1e-150], ", 10_000)
	for _, sensitive := range []bool{true, false} {
		dir := t.TempDir()
		files := map[string]string{
			"main.tf": fmt.Sprintf(`variable "s" {
  default   = "FAKE"
  sensitive = %t
}
variable "m" {
  default = { "%s" = 1 }
}
locals {
  drain = [%s]
}
resource "x_y" "a" {
  v = [var.s, var.m[1e-150]]
}
module "c" {
  source = "./c"
  v      = [var.s, var.m[1e-150]]
}
`, sensitive, key, uses),
			"c/main.tf": "variable \"v\" {}\n",
		}
		for name, src := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ctx := context.Background()
		r, err := fsutil.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		limits := DefaultLimits()
		d, err := Discover(ctx, r, limits)
		if err != nil {
			t.Fatal(err)
		}
		tree, err := LoadModuleTree(ctx, r, d, ".", limits, TreeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		root := tree.Root.Module
		vars, err := root.EvaluateVariables(ctx, r, VarOptions{}, limits)
		if err != nil {
			t.Fatal(err)
		}
		locals, err := root.EvaluateLocals(ctx, vars)
		if err != nil {
			t.Fatal(err)
		}
		res, err := root.DecodeResources(ctx, vars, locals)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || len(tree.Root.Calls) != 1 {
			t.Fatalf("got %d resources, %d calls; want 1 and 1", len(res), len(tree.Root.Calls))
		}
		inputs, err := root.ModuleInputs(ctx, tree.Root.Calls[0], vars, locals)
		if err != nil {
			t.Fatal(err)
		}
		attr := res[0].Value.GetAttr("v")
		for what, v := range map[string]cty.Value{"resource attribute": attr, "module input": inputs["v"].Value} {
			if v.IsKnown() || v.HasMark(SensitiveMark) != sensitive {
				t.Errorf("sensitive %v, %s: known %v, marked %v; want unknown, marked %v: %v",
					sensitive, what, v.IsKnown(), v.HasMark(SensitiveMark), sensitive, root.Diagnostics)
			}
		}
		// The drain is refused on line 9, the resource attribute on 12, the module input on 16.
		for _, line := range []int{9, 12, 16} {
			if !slices.ContainsFunc(root.Diagnostics, func(d Diagnostic) bool {
				return d.Summary == "Number formatting too large" && d.Line == line
			}) {
				t.Errorf("sensitive %v: diagnostics %v; want Number formatting too large on line %d", sensitive, root.Diagnostics, line)
			}
		}
	}
}

// The locals estimate keys the paths it caches by their steps, and numeric keys by the exact
// hexadecimal text of the number: decimal text took 3.8 s for 10,000 keys of 1e-150 (T-0124b).
// One value at different precisions gets one key.
func TestPathKeysWriteNumbersCheaply(t *testing.T) {
	t.Parallel()
	steps := make(hcl.Traversal, 10_000)
	for i := range steps {
		steps[i] = hcl.TraverseIndex{Key: numberAt(t, "1e-150", 512)}
	}
	start := time.Now()
	if _, ok := (usePath{key: "local.m", steps: steps}).cacheKey(); !ok {
		t.Fatal("not cached")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	key := func(v cty.Value) string {
		k, _ := usePath{key: "local.m", steps: hcl.Traversal{hcl.TraverseIndex{Key: v}}}.cacheKey()
		return k
	}
	if a, b := key(numberAt(t, "0.5", 53)), key(numberAt(t, "0.5", 512)); a != b {
		t.Errorf("0.5 keys %q and %q; want one", a, b)
	}
	if a, b := key(numberAt(t, "1e-150", 512)), key(numberAt(t, "1.0000000001e-150", 512)); a == b {
		t.Errorf("distinct numbers share key %q", a)
	}
}
