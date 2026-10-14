package terraform

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
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
