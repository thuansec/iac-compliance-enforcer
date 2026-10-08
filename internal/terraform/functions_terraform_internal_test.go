package terraform

import (
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// TestTerraformFunctions covers the edge, error and unknown cases of the functions iace
// implements itself. An error is an evaluation warning and an unknown local, as for any failed
// evaluation.
func TestTerraformFunctions(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"u":    {Value: cty.UnknownVal(cty.String)},
		"ul":   {Value: cty.UnknownVal(cty.List(cty.String))},
		"um":   {Value: cty.UnknownVal(cty.Map(cty.String))},
		"pm":   {Value: cty.MapVal(map[string]cty.Value{"a": cty.StringVal("x"), "b": cty.UnknownVal(cty.String)})},
		"tu":   {Value: cty.UnknownVal(cty.Tuple([]cty.Type{cty.String, cty.Number}))},
		"null": {Value: cty.NullVal(cty.String)},
	}
	for _, c := range []struct {
		expr string
		want string // an HCL literal; "unknown" or "error"
	}{
		// length
		{`length([1, 2, 3])`, `3`},
		{`length({ a = 1, b = "x" })`, `2`},
		{`length(tomap({ a = 1 }))`, `1`},
		{`length("")`, `0`},
		{`length("\U0001F1E9\U0001F1EA")`, `1`}, // one grapheme cluster (a flag), two code points
		{`length(var.tu)`, `2`},                 // a tuple's length is in its type
		{`length(var.ul)`, `unknown`},
		{`length(var.u)`, `unknown`},
		{`length(5)`, `error`},
		{`length(true)`, `error`},
		// coalesce
		{`coalesce(null, 2, 3)`, `2`},
		{`coalesce("", "", "a")`, `"a"`},
		{`coalesce(1, "x")`, `"1"`},
		{`coalesce(var.u, "a")`, `unknown`},
		{`coalesce("a", var.u)`, `"a"`},
		{`coalesce(null, "")`, `error`},
		{`coalesce(["a"], "b")`, `error`},
		// index
		{`index(["a", "b", "b"], "b")`, `1`},
		{`index([1, 2], 2)`, `1`},
		{`index(["a"], "z")`, `error`},
		{`index([], "a")`, `error`},
		{`index({ a = "x" }, "x")`, `error`},
		{`index(var.ul, "a")`, `unknown`},
		{`index(["a", var.u], "b")`, `unknown`},
		{`index(["b", var.u], "b")`, `0`},
		// lookup
		{`lookup({ a = "x" }, "a")`, `"x"`},
		{`lookup({ a = "x" }, "a", "d")`, `"x"`},
		{`lookup({ a = "x" }, "b", null)`, `null`},
		{`lookup({ a = "x", n = 1 }, "n", "d")`, `1`},
		{`lookup({ a = "x" }, "z", 5)`, `5`},
		{`lookup(tomap({ a = "x" }), "z", 5)`, `"5"`},
		{`lookup({ a = "x" }, "b")`, `error`},
		{`lookup({ a = "x" }, "a", "d", "e")`, `error`},
		{`lookup(tomap({ a = "x" }), "z", ["l"])`, `error`},
		{`lookup(["x"], "0", "d")`, `error`},
		{`lookup(var.um, "a", "d")`, `unknown`},
		{`lookup(var.pm, "a", "d")`, `unknown`}, // as in Terraform: the map is not wholly known
		{`lookup({ a = "x" }, var.u, "d")`, `unknown`},
		// startswith, endswith, strcontains
		{`startswith("abc", "")`, `true`},
		{`startswith("abc", "b")`, `false`},
		{`endswith("abc", "b")`, `false`},
		{`strcontains("abc", "d")`, `false`},
		{`startswith(var.u, "a")`, `unknown`},
		{`endswith(var.null, "a")`, `error`},
		// base64
		{`base64encode("")`, `""`},
		{`base64decode("")`, `""`},
		{`base64decode("not base64!")`, `error`},
		{`base64decode("/w==")`, `error`}, // decodes to 0xff, which is not UTF-8
		{`base64decode(var.u)`, `unknown`},
	} {
		m, got := evalLocal(t, c.expr, vars)
		codes := diagCodes(m)
		switch c.want {
		case "error":
			if got.IsKnown() || !slices.Equal(codes, []DiagCode{DiagEvaluation}) {
				t.Errorf("%s = %#v, diagnostics %v; want unknown with an evaluation warning", c.expr, got, m.Diagnostics)
			}
		case "unknown":
			if got.IsWhollyKnown() || len(codes) != 0 {
				t.Errorf("%s = %#v, diagnostics %v; want unknown", c.expr, got, m.Diagnostics)
			}
		default:
			want := literal(t, c.want)
			if len(codes) != 0 || !got.IsKnown() || got.IsNull() != want.IsNull() || !want.IsNull() && !got.Equals(want).True() {
				t.Errorf("%s = %#v, diagnostics %v; want %s", c.expr, got, m.Diagnostics, c.want)
			}
		}
	}
}

// TestTerraformFunctionsKeepSensitivity: a result computed from a sensitive argument is
// sensitive, including a lookup that falls back to its default.
func TestTerraformFunctionsKeepSensitivity(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"s": {Value: cty.StringVal("c2VjcmV0").Mark(SensitiveMark)},
		"m": {Value: cty.MapVal(map[string]cty.Value{"a": cty.StringVal("x")}).Mark(SensitiveMark)},
		"l": {Value: cty.ListVal([]cty.Value{cty.StringVal("x").Mark(SensitiveMark)})},
	}
	for _, expr := range []string{
		`length(var.s)`, `coalesce("", var.s)`, `index([var.s], "x")`, `lookup(var.m, "z", "d")`,
		`lookup({ a = var.s }, "a")`, `lookup({ a = "x" }, var.s, "d")`, `startswith(var.s, "c")`,
		`endswith(var.s, "c")`, `strcontains(var.s, "c")`, `base64encode(var.s)`,
		`base64decode(var.s)`, `index(var.l, "x")`,
	} {
		if _, got := evalLocal(t, expr, vars); !got.HasMark(SensitiveMark) {
			t.Errorf("%s = %#v, want sensitive", expr, got)
		}
	}
}

// TestIndexAndLengthEdgeCases: unknown sensitive arguments to index stay sensitive, a dynamic
// list gives an unknown number, and length counts a set.
func TestIndexAndLengthEdgeCases(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"sl":  {Value: cty.UnknownVal(cty.List(cty.String)).Mark(SensitiveMark)},
		"ss":  {Value: cty.UnknownVal(cty.String).Mark(SensitiveMark)},
		"dyn": {Value: cty.DynamicVal},
		"set": {Value: cty.SetVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")})},
	}
	for _, expr := range []string{`index(var.sl, "a")`, `index(["a"], var.ss)`} {
		if _, got := evalLocal(t, expr, vars); got.IsKnown() || !got.HasMark(SensitiveMark) {
			t.Errorf("%s = %#v, want unknown and sensitive", expr, got)
		}
	}
	if _, got := evalLocal(t, `index(var.dyn, 1)`, vars); got.IsKnown() || got.Type() != cty.Number {
		t.Errorf("index(var.dyn, 1) = %#v, want an unknown number", got)
	}
	if _, got := evalLocal(t, `length(var.set)`, vars); !got.RawEquals(cty.NumberIntVal(3)) {
		t.Errorf("length(var.set) = %#v, want 3", got)
	}
	// Small sets still compare.
	if _, got := evalLocal(t, `[index([var.set], var.set), contains([var.set], var.set)]`, vars); !got.RawEquals(cty.TupleVal([]cty.Value{cty.NumberIntVal(0), cty.True})) {
		t.Errorf("small set comparisons = %#v, want [0, true]", got)
	}
}

func TestSetComparisonsAreCharged(t *testing.T) {
	t.Parallel()
	// 100 numbers that differ past ten significant digits share a cty hash. (Building such a set
	// is itself quadratic, so the test keeps it small: the charge, sizes multiplied, is still
	// about 30 times the module budget.)
	colliding := func(offset int) cty.Value {
		var vals []cty.Value
		for i := range 100 {
			vals = append(vals, literal(t, "1.000000000"+strconv.Itoa(1000+offset+i)))
		}
		return cty.SetVal(vals)
	}
	vars := map[string]Variable{"a": {Value: colliding(0)}, "b": {Value: colliding(1)}}
	for _, expr := range []string{`index([var.a], var.b)`, `contains([var.a], var.b)`} {
		start := time.Now()
		m, got := evalLocal(t, expr, vars)
		if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit}) {
			t.Errorf("%s = %#v, diagnostics %v; want unknown with function_limit", expr, got, m.Diagnostics)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s took %v", expr, d)
		}
	}
	if !typeHasSet(cty.Object(map[string]cty.Type{"a": cty.Tuple([]cty.Type{cty.Map(cty.Set(cty.Number))})})) ||
		typeHasSet(cty.Object(map[string]cty.Type{"a": cty.List(cty.String)})) {
		t.Error("typeHasSet misses a nested set or finds one that is not there")
	}
}

// TestValueSizeSetElements: a set's keys are its elements, which may be unknown or marked.
func TestValueSizeSetElements(t *testing.T) {
	t.Parallel()
	v := cty.SetVal([]cty.Value{cty.UnknownVal(cty.String), cty.StringVal("ab").Mark(SensitiveMark)})
	if n, ok := valueSize(v, 100, maxNesting); !ok || n < 3 {
		t.Errorf("valueSize = %d, %v", n, ok)
	}
}
