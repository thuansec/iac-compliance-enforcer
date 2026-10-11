package terraform

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// collidingSet returns n numbers that share cty's number hash (it hashes ten significant
// digits), as a tuple and as a set: building a set of them compares every pair.
func collidingSet(n int) (tuple, set cty.Value) {
	nums := collidingNumberVals(n)
	return cty.TupleVal(nums), cty.SetVal(nums)
}

// colliding1500 is collidingSet(1_500), built once: building a set of colliding numbers
// compares every pair, about 3 s, and ten times that under the race detector.
var colliding1500 = sync.OnceValues(func() (tuple, set cty.Value) { return collidingSet(1_500) })

// collidingNumberVals returns n numbers that share cty's number hash. Building a set of them takes
// seconds, so tests that need only a tuple use this.
func collidingNumberVals(n int) []cty.Value {
	nums := make([]cty.Value, n)
	for i := range nums {
		nums[i] = cty.NumberFloatVal(1 + float64(i)/1e15)
	}
	return nums
}

// Converting values into a set type builds the set, and colliding numbers make that compare
// every pair: 1,000 of them took 1.4 s in a conditional, in lookup's default, in tolist and in
// tomap, uncharged (T-0105b review, T-0116 probe). The conversion is charged the set build, so
// such an expression is unknown with a limit warning.
func TestConversionsIntoSetsAreBounded(t *testing.T) {
	t.Parallel()
	tup, set := colliding1500()
	strs := make([]cty.Value, 1_500)
	unknowns := make([]cty.Value, 8_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprintf("1.%015d", i)) // numbers once converted
	}
	for i := range unknowns {
		unknowns[i] = cty.UnknownVal(cty.String)
	}
	vars := map[string]Variable{
		"t":  {Name: "t", Value: tup},
		"s":  {Name: "s", Value: set},
		"ns": {Name: "ns", Value: cty.TupleVal(strs)},
		"u":  {Name: "u", Value: cty.TupleVal(unknowns)},
		"n":  {Name: "n", Value: cty.NullVal(set.Type())},
		"m":  {Name: "m", Value: cty.MapVal(map[string]cty.Value{"a": set})},
	}
	for expr, builds := range map[string]bool{
		`true ? var.t : var.s`:                 true,
		`false ? var.s : var.t`:                true,
		`true ? { a = var.t } : { a = var.s }`: true,
		`lookup(var.m, "b", var.t)`:            true,
		`tolist([var.s, var.t])`:               true,
		`tomap({ a = var.s, b = var.t })`:      true,
		`coalesce(var.t, var.s)`:               true, // converts var.t to set(number)
		`coalesce(var.n, var.t)`:               true,
		`coalescelist(var.s, var.t)`:           false, // charged already
		`concat([var.s], [var.t])`:             false, // keeps a tuple
		// Numeric strings hash as the numbers they convert to (T-0116 review).
		`true ? var.ns : var.s`:      true,
		`tolist([var.s, var.ns])`:    true,
		`lookup(var.m, "b", var.ns)`: true,
		// Unified to a third type, which holds the set.
		`true ? [var.s, var.t] : [var.t]`:                      true,
		`true ? [var.t, var.t] : [var.s]`:                      true,
		`true ? { x = { a = var.t } } : { y = { a = var.s } }`: true,
		// Every unknown hashes alike.
		`true ? var.u : toset(["a"])`: true,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			limited := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
				return d.Code == DiagFunctionLimit || d.Code == DiagExpressionTooComplex
			})
			if builds && (v.IsKnown() || !limited) {
				t.Errorf("known %v, limited %v; want unknown with a limit warning: %v", v.IsKnown(), limited, m.Diagnostics)
			}
		})
	}
}

// Distinct numbers hash apart, so converting many of them into a set costs only the hashing:
// 2,000 port numbers are not a coverage gap.
func TestDistinctSetsAreCheap(t *testing.T) {
	t.Parallel()
	ports := make([]cty.Value, 2_000)
	for i := range ports {
		ports[i] = cty.NumberIntVal(int64(1024 + i))
	}
	m, v := evalLocal(t, `true ? var.p : toset([1])`, map[string]Variable{"p": {Name: "p", Value: cty.TupleVal(ports)}})
	if !v.IsKnown() {
		t.Errorf("unknown: %v", m.Diagnostics)
	}
}

// Repeated values are kept once, so they compare with one value each: 40,000 copies of a
// string, or 3,000 nulls, convert into a set without a pairwise charge, while as many
// colliding numbers are charged. (A tuple converted into set(any) first unifies its element
// types, which is charged on its own; a list has one element type.)
func TestRepeatedSetValuesAreCheap(t *testing.T) {
	t.Parallel()
	colliding := cty.TupleVal(collidingNumberVals(3_000))
	for name, tc := range map[string]struct {
		v       cty.Value
		want    cty.Type
		charged bool
	}{
		"repeated strings":   {tupleOf(40_000, cty.StringVal("a")), cty.Set(cty.String), false},
		"nulls":              {tupleOf(3_000, cty.NullVal(cty.Number)), cty.Set(cty.Number), false},
		"colliding numbers":  {colliding, cty.Set(cty.Number), true},
		"repeated into any":  {cty.ListVal(slices.Repeat([]cty.Value{cty.StringVal("a")}, 40_000)), cty.Set(cty.DynamicPseudoType), false},
		"colliding into any": {colliding, cty.Set(cty.DynamicPseudoType), true},
	} {
		cost := conversionCost(tc.v, tc.want, maxFunctionWork)
		if got := cost > maxFunctionWork/4; got != tc.charged {
			t.Errorf("%s: cost %d, want charged = %v", name, cost, tc.charged)
		}
	}
}
