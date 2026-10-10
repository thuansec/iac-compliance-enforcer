package terraform

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// doublingChain is a module whose local u_k is a conditional over two copies of u_{k-1}: with
// the condition unknown, each value is a small unknown whose type doubles per local.
func doublingChain(n int) string {
	var b strings.Builder
	b.WriteString("locals {\n  u0 = [var.x]\n")
	for k := 1; k <= n; k++ {
		fmt.Fprintf(&b, "  u%d = var.c ? [local.u%d, local.u%d] : [local.u%d, local.u%d]\n", k, k-1, k-1, k-1, k-1)
	}
	b.WriteString("}\n")
	return b.String()
}

// A value's type can grow faster than its size: unknown values of a type doubling per local,
// which cty walks when it unifies or compares types (22 locals: 14 s; T-0114c review). The
// size of an unknown value counts its expanded type, so such a local is unknown with a limit
// warning, and the conditionals over the largest types allowed are charged their walk
// (T-0114f).
func TestTypesGrowingFasterThanValuesAreBounded(t *testing.T) {
	t.Parallel()
	m := parseLocalsModule(t, doublingChain(40))
	start := time.Now()
	locals, err := m.EvaluateLocals(t.Context(), map[string]Variable{
		"c": {Name: "c", Value: cty.UnknownVal(cty.Bool)},
		"x": {Name: "x", Value: cty.StringVal("a")},
	})
	if err != nil {
		t.Fatal(err)
	}
	limit := 3 * time.Second
	if raceEnabled {
		limit *= 10
	}
	if elapsed := time.Since(start); elapsed > limit {
		t.Errorf("took %v", elapsed)
	}
	if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagValueTooLarge }) {
		t.Errorf("no value_too_large: %v", m.Diagnostics)
	}
	if ty := locals["u40"].Value.Type(); ty != cty.DynamicPseudoType && typeSize(ty, maxLocalValueSize, maxNesting) > maxLocalValueSize {
		t.Errorf("u40 has a type over the limit")
	}
	// The first locals are small and unaffected.
	if got := locals["u3"].Value.Type(); !got.IsTupleType() {
		t.Errorf("u3 has type %s, want a tuple type", got.FriendlyName())
	}
}

// typeSize counts the expanded type: a type reused in several places counts each time.
func TestTypeSize(t *testing.T) {
	t.Parallel()
	pair := cty.Tuple([]cty.Type{cty.String, cty.String})
	for name, tc := range map[string]struct {
		ty   cty.Type
		want int
	}{
		"primitive": {cty.String, 1},
		"list":      {cty.List(cty.String), 2},
		"pair":      {pair, 3},
		"nested":    {cty.Tuple([]cty.Type{pair, pair}), 7},
		"object":    {cty.Object(map[string]cty.Type{"a": pair, "b": cty.Number}), 5},
	} {
		if got := typeSize(tc.ty, 100, maxNesting); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
	if got := typeSize(cty.Tuple([]cty.Type{pair, pair}), 4, maxNesting); got <= 4 {
		t.Errorf("past the limit: %d, want more than 4", got)
	}
	if got := typeSize(cty.List(cty.List(cty.String)), 100, 1); got <= 100 {
		t.Errorf("past the depth: %d, want more than the limit", got)
	}
}

// An unknown or null value, or an empty collection, is as large as its type.
func TestValueSizeCountsTypes(t *testing.T) {
	t.Parallel()
	pair := cty.Tuple([]cty.Type{cty.String, cty.String})
	for name, tc := range map[string]struct {
		v    cty.Value
		want int
	}{
		"unknown string":      {cty.UnknownVal(cty.String), 1},
		"dynamic":             {cty.DynamicVal, 1},
		"unknown pair":        {cty.UnknownVal(pair), 3},
		"null pair":           {cty.NullVal(pair), 3},
		"empty list of pairs": {cty.ListValEmpty(pair), 4},
		"known pair":          {cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}), 5},
	} {
		if got, ok := valueSize(tc.v, 100, maxNesting); !ok || got != tc.want {
			t.Errorf("%s: %d, %v; want %d", name, got, ok, tc.want)
		}
	}
}

// The largest types allowed still take cty a long walk to unify, once per level they nest
// (Type.Equals at each level), so conditionals over them are charged that walk even when the
// types are equal, and many of them reach the function work limit instead of taking seconds.
func TestUnifyingLargeEqualTypesIsCharged(t *testing.T) {
	t.Parallel()
	src := strings.TrimSuffix(doublingChain(15), "}\n")
	for i := range 40 {
		src += fmt.Sprintf("  w%d = var.c ? local.u15 : local.u15\n", i)
	}
	m := parseLocalsModule(t, src+"}\n")
	start := time.Now()
	locals, err := m.EvaluateLocals(t.Context(), map[string]Variable{
		"c": {Name: "c", Value: cty.UnknownVal(cty.Bool)},
		"x": {Name: "x", Value: cty.StringVal("a")},
	})
	if err != nil {
		t.Fatal(err)
	}
	limit := 3 * time.Second
	if raceEnabled {
		limit *= 10
	}
	if elapsed := time.Since(start); elapsed > limit {
		t.Errorf("took %v", elapsed)
	}
	if ty := locals["u15"].Value.Type(); ty == cty.DynamicPseudoType {
		t.Fatalf("u15 is over the limit; the test needs the largest type allowed: %v", m.Diagnostics)
	}
	if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Conditional too large" }) {
		t.Errorf("no limit warning: %v", m.Diagnostics)
	}
}

// doubledType is a tuple type nested k deep, each level two copies of the one below: 2^(k+1) - 1
// types expanded.
func doubledType(k int) cty.Type {
	ty := cty.String
	for range k {
		ty = cty.Tuple([]cty.Type{ty, ty})
	}
	return ty
}

// The type-size limit holds at, just below and just above the limit, for unknown and null
// values and for values holding them, whatever their own size (T-0114f review: an oversized
// type left the size exactly at the limit, which passed).
func TestValueSizeLimitsTypes(t *testing.T) {
	t.Parallel()
	ty := doubledType(9) // 1,023 types
	for name, tc := range map[string]struct {
		v     cty.Value
		limit int
		ok    bool
	}{
		"unknown at the limit":    {cty.UnknownVal(ty), 1023, true},
		"unknown below the limit": {cty.UnknownVal(ty), 1024, true},
		"unknown above the limit": {cty.UnknownVal(ty), 1022, false},
		"null above the limit":    {cty.NullVal(ty), 1022, false},
		"null at the limit":       {cty.NullVal(ty), 1023, true},
		"tuple of unknowns":       {cty.TupleVal([]cty.Value{cty.UnknownVal(ty), cty.UnknownVal(ty)}), 2047, true},
		"tuple of unknowns above": {cty.TupleVal([]cty.Value{cty.UnknownVal(ty), cty.UnknownVal(ty)}), 2046, false},
		"far larger type":         {cty.UnknownVal(doubledType(20)), 10, false},
		"far larger in a tuple":   {cty.TupleVal(slices.Repeat([]cty.Value{cty.UnknownVal(doubledType(20))}, 1000)), 1 << 18, false},
		"type nested too deeply":  {cty.UnknownVal(nestedListType(maxNesting + 1)), 1 << 18, false},
	} {
		if _, ok := valueSize(tc.v, tc.limit, maxNesting); ok != tc.ok {
			t.Errorf("%s: fits %v, want %v", name, ok, tc.ok)
		}
	}
}

// nestedListType is a list type nested n deep.
func nestedListType(n int) cty.Type {
	ty := cty.String
	for range n {
		ty = cty.List(ty)
	}
	return ty
}

// A type over the limit built within one expression, from a value that fits on its own, is
// refused: here the locals estimate sees the for expression's iterations before evaluation.
// TestValueSizeLimitsTypes proves the check after evaluation, which catches what no estimate
// sees.
func TestBuiltTypesAreBounded(t *testing.T) {
	t.Parallel()
	u := cty.UnknownVal(doubledType(15)) // 65,535 types: fits on its own
	m, v := evalLocal(t, `[for i in range(5) : var.u]`, map[string]Variable{"u": {Name: "u", Value: u}})
	if v.Type() != cty.DynamicPseudoType {
		t.Errorf("value of type size %d passed", typeSize(v.Type(), maxLocalValueSize, maxNesting))
	}
	if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagValueTooLarge }) {
		t.Errorf("no value_too_large: %v", m.Diagnostics)
	}
}

// A deep chain, each local one level deeper than the last, is charged cty's walk at every level:
// 3,000 locals took 95 s, and a chain comparing the levels 65 s (T-0114f review).
func TestDeepTypeChainsAreBounded(t *testing.T) {
	t.Parallel()
	for name, line := range map[string]string{
		"conditional": "  u%d = var.c ? [local.u%d] : [local.u%d]%.0d%.0d\n",
		"comparison":  "  u%d = [local.u%d] == [local.u%d] ? [local.u%d] : [local.u%d]\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			b.WriteString("locals {\n  u0 = [var.x]\n")
			for k := 1; k <= 3_000; k++ {
				fmt.Fprintf(&b, line, k, k-1, k-1, k-1, k-1)
			}
			b.WriteString("}\n")
			m := parseLocalsModule(t, b.String())
			start := time.Now()
			if _, err := m.EvaluateLocals(t.Context(), map[string]Variable{
				"c": {Name: "c", Value: cty.UnknownVal(cty.Bool)},
				"x": {Name: "x", Value: cty.UnknownVal(cty.String)},
			}); err != nil {
				t.Fatal(err)
			}
			limit := 5 * time.Second
			if raceEnabled {
				limit *= 10
			}
			if elapsed := time.Since(start); elapsed > limit {
				t.Errorf("took %v", elapsed)
			}
		})
	}
}
