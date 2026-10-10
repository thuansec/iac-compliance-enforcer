package terraform

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// A conditional's wrappers take their results as capsules (ADR 0033), so cty walks nothing for
// marks, and a conditional is not charged as walking its inputs: `var.c ? var.t : null` over
// 3,000 elements cost about 144k units per evaluation, so about 58 instances spent a module's
// function work (T-0114e review, T-0114i).
func TestConditionalsDoNotWalkTheirResults(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"t": {Name: "t", Value: tupleOf(3_000, cty.StringVal("10.0.0.0/24"))},
		"c": {Name: "c", Value: cty.UnknownVal(cty.Bool)},
	}
	for expr, max := range map[string]int{
		`var.c ? var.t : null`:  0,
		`false ? null : var.t`:  0,
		`var.c ? var.t : var.t`: 13_000, // equal types: cty's unification walk (ADR 0031)
	} {
		m, _ := evalLocal(t, expr, vars)
		if m.fnWork > max {
			t.Errorf("%s: charged %d, want at most %d", expr, m.fnWork, max)
		}
	}
	if m, _ := evalLocal(t, `length(var.t) > 0 ? var.t : null`, vars); m.fnWork < 36_001*argumentWalkWork {
		t.Errorf("a call and an operator: charged %d, want their full walk", m.fnWork)
	}
}

// Shapes that cost cty most to walk per unit (scalars, sets, which it sorts to iterate) and
// conditionals nested 100 deep with the condition known, evaluated by 300 instances, finish within
// the module time budget: the results are not walked at all (T-0114i review: 22 s and 51 s
// while walked).
func TestConditionalsOverCostlyShapesAreFast(t *testing.T) {
	t.Parallel()
	nums := make([]cty.Value, 20_000)
	for i := range nums {
		nums[i] = cty.NumberIntVal(int64(i))
	}
	nested := "var.v"
	for range 100 {
		nested = "(var.c ? " + nested + " : null)"
	}
	for name, tc := range map[string]struct {
		v    cty.Value
		expr string
	}{
		"bools":           {tupleOf(50_000, cty.True), `var.f ? var.v : null`},
		"set of numbers":  {cty.SetVal(nums), `var.f ? var.v : null`},
		"nested 100 deep": {tupleOf(3_000, cty.StringVal("a")), nested},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := "resource \"aws_s3_bucket\" \"b\" {\n  count = 300\n  n     = " + tc.expr + "\n}\n"
			m := parseFilesModule(t, map[string]string{"main.tf": src})
			vars := map[string]Variable{
				"v": {Name: "v", Value: tc.v},
				"c": {Name: "c", Value: cty.True},
				"f": {Name: "f", Value: cty.False},
			}
			start := time.Now()
			if _, err := m.DecodeResources(t.Context(), vars, map[string]Local{}); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
				t.Errorf("a conditional over unwalked results was limited: %v", fmt.Sprint(m.Diagnostics[:1]))
			}
		})
	}
}

// Marks survive the capsule: deep in a result, on the result not taken, and through nested
// conditionals, as in hcl.
func TestConditionalsKeepMarks(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"d": {Name: "d", Value: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("FAKE").Mark(SensitiveMark)})},
		"s": {Name: "s", Value: cty.StringVal("FAKE").Mark(SensitiveMark)},
		"c": {Name: "c", Value: cty.True},
	}
	for expr, deep := range map[string]bool{
		`true ? var.d : null`:                   true,
		`true ? "x" : var.s`:                    false,
		`var.c ? (var.c ? "x" : var.s) : "y"`:   false,
		`var.c ? (var.c ? var.d : null) : null`: true,
	} {
		m, v := evalLocal(t, expr, vars)
		if got := v.ContainsMarked(); !got {
			t.Errorf("%s: %#v lost its marks: %v", expr, v, m.Diagnostics)
		}
		if deep && v.IsMarked() {
			t.Errorf("%s: the mark moved to the whole value", expr)
		}
	}
}
