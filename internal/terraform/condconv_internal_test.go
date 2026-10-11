package terraform

import (
	"fmt"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// A conditional whose result types differ is charged unifying them, twice (iace finds the type
// as hcl does), and converting each result to the type hcl unifies them to
// (convert.UnifyUnsafe), along cty's conversion path, rather than an estimate that unifies the
// element types of every collection in the results: 40,000 repeated strings converted to
// set(string) are linear, not refused (T-0114k).
func TestConditionalConversionCostFollowsCty(t *testing.T) {
	t.Parallel()
	entries := make(map[string]cty.Value, 2_000)
	for i := range 2_000 {
		entries[fmt.Sprint("k", i)] = cty.ListVal([]cty.Value{cty.NumberIntVal(1)})
	}
	for name, tc := range map[string]struct{ t, f cty.Value }{
		"tuple into set":      {tupleOf(40_000, cty.StringVal("a")), cty.SetVal([]cty.Value{cty.StringVal("b")})},
		"tuple into list":     {tupleOf(4_000, cty.StringVal("a")), cty.ListVal([]cty.Value{cty.StringVal("b")})},
		"map of lists":        {cty.MapVal(entries), cty.ObjectVal(map[string]cty.Value{"a": cty.TupleVal([]cty.Value{cty.StringVal("x")})})},
		"object into map":     {cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("x")}), cty.MapVal(map[string]cty.Value{"b": cty.StringVal("y")})},
		"nested tuples":       {cty.TupleVal([]cty.Value{tupleOf(300, cty.StringVal("a"))}), cty.ListVal([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("b")})})},
		"unknown into list":   {cty.UnknownVal(tupleOf(500, cty.StringVal("a")).Type()), cty.ListValEmpty(cty.String)},
		"numbers and strings": {cty.ListVal([]cty.Value{cty.NumberIntVal(1)}), cty.ListVal([]cty.Value{cty.StringVal("b")})},
	} {
		types := []cty.Type{tc.t.Type(), tc.f.Type()}
		u, _ := convert.UnifyUnsafe(types)
		if u == cty.NilType {
			t.Fatalf("%s: the types do not unify", name)
		}
		want := min(2*unifyTypesCost(types, maxFunctionWork)+
			conversionCost(tc.t, u, maxFunctionWork)+conversionCost(tc.f, u, maxFunctionWork), maxFunctionWork+1)
		if got := condConversionCost(tc.t, tc.f, maxFunctionWork); got != want {
			t.Errorf("%s: cost %d, want %d", name, got, want)
		}
	}
}

// Types that do not unify make hcl fail without converting anything: only the unification is
// charged, twice (iace's and hcl's).
func TestConditionalConversionCostWithoutUnification(t *testing.T) {
	t.Parallel()
	tv := tupleOf(4_000, cty.StringVal("a"))
	fv := cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("x")})
	types := []cty.Type{tv.Type(), fv.Type()}
	if got, want := condConversionCost(tv, fv, maxFunctionWork), 2*unifyTypesCost(types, maxFunctionWork); got != want {
		t.Errorf("cost %d, want %d", got, want)
	}
}

// End to end, the conditional of repeated strings and a set is known (it was refused, T-0116
// review), while the shapes whose conversion is quadratic stay refused
// (TestConditionalsChargeConversions, TestConversionsIntoSetsAreBounded).
func TestConditionalOfRepeatedStringsAndASetIsKnown(t *testing.T) {
	t.Parallel()
	m, v := evalLocal(t, `true ? var.t : toset(["b"])`, map[string]Variable{
		"t": {Name: "t", Value: tupleOf(40_000, cty.StringVal("a"))},
	})
	if !v.IsKnown() {
		t.Errorf("unknown: %v", m.Diagnostics)
	}
}

// A conditional of 40,000 distinct strings and a set, now accepted, takes about 27 ms in cty, so
// repeating it 300 times would take seconds. The repetitions stop at the module's work. Each
// iteration pays its reference to var.t (the for body's charge), which bounds this before the
// conversion's hashing does, so this guards the end-to-end bound, and TestSetBuildChargesHashing
// the charge itself (locals cannot repeat it: their size limits refuse such values first).
func TestRepeatedConditionalsIntoSetsAreBounded(t *testing.T) { // not parallel: it measures time
	strs := make([]cty.Value, 40_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("user-", i))
	}
	start := time.Now()
	m, v := evalLocal(t, `[for i in range(300) : true ? var.t : toset(["b"])]`, map[string]Variable{
		"t": {Name: "t", Value: cty.TupleVal(strs)},
	})
	if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	if v.IsKnown() {
		t.Errorf("known; want unknown with a limit warning: %v", m.Diagnostics)
	}
}

// Converting distinct values into a set costs at least their hashing and insertion, and a tuple
// unified with a set takes cty's general path, which walks the types once instead of unifying
// the tuple's element types.
func TestSetBuildChargesHashing(t *testing.T) {
	t.Parallel()
	tv := tupleOf(40_000, cty.StringVal("a"))
	if got := conversionCost(tv, cty.Set(cty.String), maxFunctionWork); got < 40_000*(1+setInsertWork) {
		t.Errorf("cost %d, want at least %d", got, 40_000*(1+setInsertWork))
	}
	types := []cty.Type{tv.Type(), cty.Set(cty.String)}
	if got := unifyTypesCost(types, maxFunctionWork); got > 2*40_001 {
		t.Errorf("unifying a tuple and a set costs %d, want at most %d", got, 2*40_001)
	}
	// A set of the dynamic type makes cty unify the tuple's element types to convert it.
	mixed := tupleOf(40_000, cty.StringVal("a"), cty.NumberIntVal(1))
	if got := unifyTypesCost([]cty.Type{mixed.Type(), cty.Set(cty.DynamicPseudoType)}, maxFunctionWork); got <= maxFunctionWork {
		t.Errorf("unifying a mixed tuple and a set of any costs %d, want refused", got)
	}
}
