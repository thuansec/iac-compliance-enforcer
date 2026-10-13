package terraform

import (
	"fmt"
	"math/bits"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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

// cty keeps one copy of equal values, compound ones included, so repeated objects or lists
// compare with one value each: 3,000 copies of {a = "x"} convert into a set in linear time,
// while 3,000 objects around colliding numbers, distinct but sharing a hash, are still charged
// pairwise (T-0116c).
func TestRepeatedCompoundSetValuesAreCheap(t *testing.T) {
	t.Parallel()
	obj := cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("x"), "n": cty.NumberIntVal(1)})
	objT := obj.Type()
	colliding := make([]cty.Value, 3_000)
	for i, n := range collidingNumberVals(3_000) {
		colliding[i] = cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("x"), "n": n})
	}
	for name, tc := range map[string]struct {
		v       cty.Value
		want    cty.Type
		charged bool
	}{
		"repeated objects":   {tupleOf(3_000, obj), cty.Set(objT), false},
		"repeated lists":     {tupleOf(3_000, cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})), cty.Set(cty.List(cty.String)), false},
		"colliding objects":  {cty.TupleVal(colliding), cty.Set(objT), true},
		"objects with nulls": {tupleOf(3_000, cty.ObjectVal(map[string]cty.Value{"a": cty.NullVal(cty.String), "n": cty.NumberIntVal(1)})), cty.Set(objT), false},
	} {
		cost := conversionCost(tc.v, tc.want, maxFunctionWork)
		if got := cost > maxFunctionWork/4; got != tc.charged {
			t.Errorf("%s: cost %d, want charged = %v", name, cost, tc.charged)
		}
	}
	// End to end, the conditional of repeated objects is known (T-0116 review).
	m, v := evalLocal(t, `true ? var.t : toset([{ a = "y", n = 2 }])`, map[string]Variable{"t": {Name: "t", Value: tupleOf(3_000, obj)}})
	if !v.IsKnown() {
		t.Errorf("conditional unknown: %v", m.Diagnostics)
	}
}

// Building a set of compound elements converts each to the element type, as cty does, and so
// does the estimate, to hash them as cty does: the estimate's conversions are charged too, so
// an accepted conversion costs about its charge, not twice it (T-0116 review: 0.86 s of
// estimate plus 0.82 s of conversion for one set(list(number)) value).
func TestSetBuildChargesItsOwnConversions(t *testing.T) {
	t.Parallel()
	big := make([]cty.Value, 10_000)
	for i := range big {
		big[i] = cty.NumberIntVal(int64(i))
	}
	rows := []cty.Value{cty.TupleVal(big)}
	for i := range 700 {
		rows = append(rows, cty.TupleVal([]cty.Value{cty.NumberIntVal(int64(20_000 + i))}))
	}
	v := cty.TupleVal(rows)
	want := cty.Set(cty.List(cty.Number))
	plain := conversionCostWith(&unifyWalk{limit: maxFunctionWork, noSetBuild: true}, v, want, false)
	built := conversionCost(v, want, maxFunctionWork)
	if built < min(2*plain, maxFunctionWork+1) { // past the limit, a cost is the limit plus one
		t.Errorf("with the set build %d, without %d; want the elements' conversions charged again", built, plain)
	}
}

// The estimate repeats what cty does to build a set of a tuple: it unifies the element types to
// find the target (charged again) and converts each element (a primitive's formatting, charged
// again), so the build costs at least twice those (T-0116c).
func TestSetBuildChargesItsRepeats(t *testing.T) {
	t.Parallel()
	nums := make([]cty.Value, 2_000)
	weights := 0
	for i := range nums {
		nums[i] = cty.NumberIntVal(int64(i))
		w, _ := comparisonWeight(nums[i])
		weights += w
	}
	v := cty.TupleVal(append(nums, cty.StringVal("x")))
	if got, want := conversionCost(v, cty.Set(cty.String), maxFunctionWork), 2*weights; got < want {
		t.Errorf("into set(string): cost %d, want at least %d (formatting twice)", got, want)
	}
	anySet := cty.Set(cty.DynamicPseudoType)
	plain := conversionCostWith(&unifyWalk{limit: maxFunctionWork, noSetBuild: true}, v, anySet, false)
	built := conversionCost(v, anySet, maxFunctionWork)
	if got, want := built-plain, pairs(len(nums)+1)+weights; got < want {
		t.Errorf("into set(any): the build costs %d, want at least %d (unifying again, then hashing)", got, want)
	}
}

// A refused conversion into set(any) reports the work its estimate really did (unifyWalk.done:
// the unification it ran and the elements it hashed), which chargeConversion spends, so a
// refused variable cannot repeat it for free (T-0116c review).
func TestRefusedSetAnyConversionReportsItsWork(t *testing.T) {
	t.Parallel()
	v := cty.TupleVal(collidingNumberVals(3_000))
	cost, done := conversionCostDone(v, cty.Set(cty.DynamicPseudoType), false, maxFunctionWork)
	if cost <= maxFunctionWork || done < 3_000 {
		t.Errorf("cost %d, done %d; want refused with the hashing of 3,000 elements done", cost, done)
	}
}

// Converting a tuple into a set builds a set that whatever receives it iterates, and so sorts,
// at least once: cty walks a function's arguments for marks before anything can measure them.
// Three locals `length(true ? var.t : toset([["a", …, "g"]]))` over a tuple of 12,000 tuples of
// numbers took 2.0 s (T-0116g): each local converted the tuple, and cty walked each set built,
// sorting it, for free. The conversion now charges the built set's sort, so the first local
// uses most of the module's work and the others are refused before converting: the three cost
// about the first one, a few times its conversion estimate (T-0116h).
func TestConversionsChargeTheSetsTheyBuild(t *testing.T) { // not parallel: it measures time
	tup := cty.TupleVal(numberTupleSet(12_000).AsValueSlice())
	start := time.Now()
	condConversionCost(tup, cty.SetVal([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a")})}), maxFunctionWork)
	estimate := time.Since(start)
	const local = `length(true ? var.t : toset([["a", "b", "c", "d", "e", "f", "g"]]))`
	m := parseLocalsModule(t, "locals {\n  a = "+local+"\n  b = "+local+"\n  c = "+local+"\n}\n")
	start = time.Now()
	if _, err := m.EvaluateLocals(t.Context(), map[string]Variable{"t": {Name: "t", Value: tup}}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*estimate+100*time.Millisecond*raceSlowdown {
		t.Errorf("took %v; one conversion estimate takes %v", elapsed, estimate)
	}
	// The charge covers one sort of the set built, as measuring it would count it.
	rows := make([]cty.Value, 1_000)
	for i := range rows {
		rows[i] = tupleOf(4, cty.StringVal(fmt.Sprint(i)))
	}
	want := cty.Set(cty.List(cty.String))
	built, err := convert.Convert(cty.TupleVal(rows), want)
	if err != nil {
		t.Fatal(err)
	}
	_, sort, _ := valueSizeWalk(built, maxFunctionWork, maxFunctionWork, maxNesting)
	if cost := conversionCost(cty.TupleVal(rows), want, maxFunctionWork); cost < sort {
		t.Errorf("cost %d, below the built set's sort %d", cost, sort)
	}
}

// Converting a set iterates it twice, the estimate and cty, each sorting it: the cost covers
// both sorts. A set too costly to sort is refused before the estimate iterates it.
func TestConvertingSetsChargesTheirSorts(t *testing.T) {
	t.Parallel()
	s := tupleSet(1_000, 4)
	_, sort, _ := valueSizeWalk(s, maxFunctionWork, maxFunctionWork, maxNesting)
	if cost := conversionCost(s, cty.List(cty.List(cty.String)), maxFunctionWork); cost < 2*sort {
		t.Errorf("cost %d, below twice the set's sort %d", cost, sort)
	}
	big := tupleSet(40_000, 7)
	start := time.Now()
	if cost := conversionCost(big, cty.List(cty.List(cty.String)), maxFunctionWork/4); cost <= maxFunctionWork/4 {
		t.Errorf("accepted at %d", cost)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond*raceSlowdown {
		t.Errorf("refusing took %v; want no iteration", elapsed)
	}
}

// A refused conversion spends the work its estimate did (conversionCostDone), the sorts of the
// sets it iterated included: a set whose lower bound fits but whose sort does not is iterated,
// and so sorted, before it is refused, and a refused variable conversion must not repeat that
// for free (T-0116h review: 0.35 s of sorting spent as its lower bound alone).
func TestRefusedConversionsSpendTheirSorts(t *testing.T) {
	t.Parallel()
	s := tupleSet(700, 50)
	_, sort, ok := valueSizeWalk(s, maxFunctionWork, maxFunctionWork, maxNesting)
	if !ok {
		t.Fatal("measuring refused")
	}
	floor := 700 * bits.Len(700) * elementSortFloor(s.Type().ElementType(), maxFunctionWork)
	limit := (floor + sort) / 2 // the lower bound fits, the sort does not
	if floor >= limit {
		t.Fatalf("floor %d, sort %d: want a set whose sort passes its lower bound", floor, sort)
	}
	cost, done := conversionCostDone(s, cty.List(cty.List(cty.String)), false, limit)
	if cost <= limit || done < limit {
		t.Errorf("cost %d, done %d with limit %d; want refused, having done the sort it walked", cost, done, limit)
	}
}
