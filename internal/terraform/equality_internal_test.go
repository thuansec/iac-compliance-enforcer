package terraform

import (
	"fmt"
	"math/big"
	"math/bits"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// cty compares two sets by looking each element of one up in the other, and colliding number
// hashes (cty hashes ten significant digits) make every lookup compare every element:
// `var.s == var.s` over 1,000 colliding numbers took 2.7 s (T-0116 probe). hcl evaluates
// operators itself, so the right operand is wrapped and the comparison charged with both
// operands in hand; over the limit it is unknown with a warning (T-0116b).
func TestSetEqualityIsBounded(t *testing.T) {
	t.Parallel()
	_, colliding := colliding1500()
	strs := make([]cty.Value, 2_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("user-", i))
	}
	distinct := cty.SetVal(strs)
	vars := map[string]Variable{
		"s": {Name: "s", Value: colliding},
		"d": {Name: "d", Value: distinct},
		"o": {Name: "o", Value: cty.ObjectVal(map[string]cty.Value{"tags": colliding})},
		"l": {Name: "l", Value: cty.ListVal([]cty.Value{colliding})},
	}
	for expr, known := range map[string]bool{
		`var.s == var.s`:         false,
		`var.s != var.s`:         false,
		`var.o == var.o`:         false, // a set inside an object
		`var.l == var.l`:         false, // a set inside a list
		`[var.s] == [var.s]`:     false,
		`var.s == var.s ? 1 : 2`: false,
		// Distinct values hash apart: each lookup compares one element.
		`var.d == var.d`: true,
		`var.d != var.d`: true,
		// Different types and nulls are decided without comparing elements.
		`var.s == var.d`: true,
		`var.s == null`:  true,
		`var.s == "x"`:   true,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() != known {
				t.Errorf("known %v, want %v: %v", v.IsKnown(), known, m.Diagnostics)
			}
			limited := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Comparison too large" })
			if limited == known {
				t.Errorf("limit warning %v, want %v: %v", limited, !known, m.Diagnostics)
			}
		})
	}
}

// Comparisons of primitive values are not charged, and shallow structures without sets cost
// about their size: all evaluate as before.
func TestEqualityWithoutSetsIsUnchanged(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"t": {Name: "t", Value: tupleOf(20_000, cty.StringVal("a"))},
		"e": {Name: "e", Value: cty.StringVal("prod")},
	}
	for expr, want := range map[string]cty.Value{
		`var.t == var.t`:               cty.True,
		`var.e == "prod"`:              cty.True,
		`var.e != "prod"`:              cty.False,
		`toset(["a"]) == toset(["a"])`: cty.True,
		`toset(["a"]) != toset(["b"])`: cty.True,
		`(var.e == "prod") == true`:    cty.True,
	} {
		m, v := evalLocal(t, expr, vars)
		if !v.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v: %v", expr, v, want, m.Diagnostics)
		}
	}
}

// The rewritten equality operators evaluate exactly as hcl's: values, unknowns, nulls, marks,
// refinements and errors, with sets in them or not (T-0116b).
func TestEqualityMatchesHCL(t *testing.T) {
	t.Parallel()
	set := cty.SetVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})
	vars := cty.ObjectVal(map[string]cty.Value{
		"s":  set,
		"z":  cty.SetVal([]cty.Value{cty.StringVal("a")}),
		"u":  cty.UnknownVal(set.Type()),
		"us": cty.SetVal([]cty.Value{cty.UnknownVal(cty.String)}),
		"n":  cty.NullVal(set.Type()),
		"m":  set.Mark(SensitiveMark),
		"dm": cty.SetVal([]cty.Value{cty.StringVal("a").Mark(SensitiveMark)}),
		"o":  cty.ObjectVal(map[string]cty.Value{"tags": set, "name": cty.StringVal("x")}),
		"e":  cty.StringVal("prod"),
	})
	for _, expr := range []string{
		`var.s == var.s`, `var.s != var.z`, `var.s == var.u`, `var.s == var.us`,
		`var.s == var.n`, `var.n == null`, `var.s != null`, `var.m == var.s`, `var.dm == var.z`,
		`var.o == var.o`, `var.o == { tags = var.s, name = "y" }`, `var.s == ["a", "b"]`,
		`var.e == "prod"`, `var.o.missing == var.s`, `var.s == var.o.missing`,
		`(var.s == var.s) == (var.z != var.s)`, `[for x in var.s : x == "a"]`,
		`var.s == var.s ? "same" : "different"`, `"${var.s == var.z}"`,
		`try(var.o.missing == var.s, "fallback")`,
	} {
		plain, diags := hclsyntax.ParseExpression([]byte(expr), "x.tf", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", expr, diags)
		}
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": vars}, Functions: plainFunctions()}
		want, wantDiags := plain.Value(ctx)

		rewritten, _ := hclsyntax.ParseExpression([]byte(expr), "x.tf", hcl.InitialPos)
		rewriteForExprs(rewritten)
		rewriteForExprs(rewritten) // idempotent
		m := &ParsedModule{}
		rctx := &hcl.EvalContext{Variables: ctx.Variables, Functions: plainFunctions()}
		for n, f := range m.forFunctionsAnd() {
			rctx.Functions[n] = f
		}
		got, gotDiags := rewritten.Value(rctx)
		if !got.RawEquals(want) || wantDiags.HasErrors() != gotDiags.HasErrors() || len(wantDiags) != len(gotDiags) {
			t.Errorf("%s: iace %#v %v; hcl %#v %v", expr, got, gotDiags, want, wantDiags)
		}
		if m.cmpLimited {
			t.Errorf("%s: limited", expr)
		}
	}
}

// A refused comparison makes the whole expression unknown, keeping the sensitivity of every
// value in it.
func TestRefusedComparisonStaysSensitive(t *testing.T) {
	t.Parallel()
	_, colliding := colliding1500()
	m, v := evalLocal(t, `{ a = var.k, b = var.s == var.s }`, map[string]Variable{
		"k": {Name: "k", Value: cty.StringVal("FAKE").Mark(SensitiveMark)},
		"s": {Name: "s", Value: colliding},
	})
	if v.IsKnown() || !v.HasMark(SensitiveMark) {
		t.Errorf("known %v, sensitive %v; want unknown and sensitive: %v", v.IsKnown(), v.HasMark(SensitiveMark), m.Diagnostics)
	}
}

// The right-operand wrapper takes its state as a capsule only the rewrite can create: a
// configuration that calls it itself fails on that argument and reaches no comparison's state.
func TestHandWrittenComparisonWrapperFails(t *testing.T) {
	t.Parallel()
	m, v := evalLocal(t, `__iace_cmp_right(1, toset(["a"]))`, nil)
	if v.IsKnown() || !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
		return d.Summary == "Invalid function argument"
	}) {
		t.Errorf("value %#v, diagnostics %v; want unknown with an invalid argument", v, m.Diagnostics)
	}
}

// Repeating a refused comparison stops at the module's work instead of costing seconds per
// repetition (T-0116b): each refusal spends the work it charged, so the loop ends at about the
// module's whole work (1.4 s without -race when equalityCost walked the sets before refusing,
// T-0116c review; with equalityCost removed it took 192 s). Since the estimate's walks are
// charged first (T-0116f) the loop takes about 10 ms, and accepted comparisons of colliding
// numbers measure 38 to 56 ns per unit (T-0116e sweep, 50 to 400 elements), so the bucket
// charge is kept. Each iteration also pays its references to var.s, but at 600 elements those
// alone no longer stop it.
func TestRepeatedRefusedComparisonsAreBounded(t *testing.T) { // not parallel: it measures time
	_, colliding := collidingSet(600) // refused, and quick to build
	start := time.Now()
	m, v := evalLocal(t, `[for i in range(200) : var.s == var.s]`, map[string]Variable{"s": {Name: "s", Value: colliding}})
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	if v.IsKnown() {
		t.Errorf("known; want unknown: %v", m.Diagnostics)
	}
}

// What the charge accepts, cty compares quickly: sets of distinct strings, numbers and small
// objects at the sizes a configuration holds, and colliding numbers below the limit; the
// timing sweep that calibrated setSortWork measured at most about 95 ns per unit.
func TestAcceptedSetComparisonsAreFast(t *testing.T) {
	t.Parallel()
	strs := make([]cty.Value, 3_000)
	objs := make([]cty.Value, 800)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("user-", i))
	}
	for i := range objs {
		objs[i] = cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal(fmt.Sprint(i)), "b": cty.NumberIntVal(int64(i))})
	}
	_, colliding := collidingSet(150)
	lists := make([]cty.Value, 20) // compound elements around colliding numbers
	for i := range lists {
		lists[i] = nestedList(10, cty.NumberFloatVal(1+float64(i)/1e15))
	}
	for name, s := range map[string]cty.Value{
		"strings": cty.SetVal(strs), "objects": cty.SetVal(objs), "colliding": colliding, "colliding lists": cty.SetVal(lists),
	} {
		other := cty.SetVal(s.AsValueSlice()) // an equal set built apart
		cost := equalityCost(s, other, maxFunctionWork)
		if cost > maxFunctionWork {
			t.Errorf("%s: refused (%d)", name, cost)
			continue
		}
		start := time.Now()
		s.Equals(other)
		if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
			t.Errorf("%s: cty took %v for a charge of %d", name, elapsed, cost)
		}
	}
}

// cty's Equals walks each operand's subtree for marks again at every level it recurses into,
// sorting every set it meets, so nested values multiply the work by their depth: a 400-deep
// list around a set of 2,000 strings took 66 s for three comparisons, and a 400-deep tuple
// around 20,000 strings 4.5 s per comparison, with no set at all (T-0116b review). Comparisons
// of nested values are charged that depth-weighted walk.
func TestDeepEqualityIsBounded(t *testing.T) {
	t.Parallel()
	strs := make([]cty.Value, 2_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("user-", i))
	}
	vars := map[string]Variable{
		"s": {Name: "s", Value: nestedList(200, cty.SetVal(strs))},
		"t": {Name: "t", Value: nestedTuple(400, tupleOf(20_000, cty.StringVal("a")))},
		"f": {Name: "f", Value: nestedTuple(3, tupleOf(200, cty.StringVal("a")))},
	}
	for expr, known := range map[string]bool{
		`var.s == var.s`: false,
		`var.t == var.t`: false,
		`var.f == var.f`: true, // shallow and small
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() != known {
				t.Errorf("known %v, want %v: %v", v.IsKnown(), known, m.Diagnostics)
			}
		})
	}
}

// A refused comparison spends the work it was charged, up to the module's work, so it cannot
// repeat for free.
func TestRefusedComparisonSpendsItsWork(t *testing.T) {
	t.Parallel()
	_, colliding := colliding1500()
	m, v := evalLocal(t, `var.s == var.s`, map[string]Variable{"s": {Name: "s", Value: colliding}})
	if v.IsKnown() || m.fnWork != maxFunctionWork {
		t.Errorf("known %v, work %d; want unknown with all %d spent", v.IsKnown(), m.fnWork, maxFunctionWork)
	}
}

// Sorting a set of numbers formats each non-integer as exact decimals on every comparison
// (setRules.Less, RawEquals), on top of the comparison weight, which counts formatting once:
// 400 thirds at 512 bits were accepted at 290 ns per unit (T-0116b review), and charging the
// formatting twice per level measured about 80 ns. Each side is sorted twice (the marks walk and
// Equals), so the cost is at least 2 × 2 × 2 × levels × the formatting of every element.
func TestSetsOfFractionsPayTheirSort(t *testing.T) {
	t.Parallel()
	nums := make([]cty.Value, 400)
	format := 0
	for i := range nums {
		third := new(big.Float).SetPrec(512).Quo(big.NewFloat(float64(i+1)), big.NewFloat(3))
		nums[i] = cty.NumberVal(third) // 512 bits, as cty parses numbers
		format += numberFormatCost(nums[i])
	}
	a, b := cty.SetVal(nums), cty.SetVal(nums)
	levels := bits.Len(uint(len(nums)))
	if got, want := equalityCost(a, b, maxFunctionWork), 8*levels*format; got < want {
		t.Errorf("cost %d, want at least %d", got, want)
	}
}

// Compound elements around colliding numbers share a hash (it holds each number's ten-digit
// text), and cty compares two of them with a full Equals, which walks each for marks at every
// level: a set of 40 lists nested 100 deep around close numbers took 4.8 s to compare while
// charged a fifth of the limit (T-0116b review). Each pair in a bucket is charged the
// elements' own depth-weighted walks.
func TestCollidingCompoundSetsAreBounded(t *testing.T) {
	t.Parallel()
	for name, wrap := range map[string]func(cty.Value) cty.Value{
		"lists":   func(v cty.Value) cty.Value { return nestedList(100, v) },
		"objects": func(v cty.Value) cty.Value { return nestedObject(100, v) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			elems := make([]cty.Value, 40)
			for i := range elems {
				elems[i] = wrap(cty.NumberFloatVal(1 + float64(i)/1e15))
			}
			a, b := cty.SetVal(elems), cty.SetVal(elems)
			if cost := equalityCost(a, b, maxFunctionWork); cost <= maxFunctionWork {
				start := time.Now()
				a.Equals(b)
				t.Errorf("accepted at %d units; cty took %v", cost, time.Since(start))
			}
		})
	}
}

// nestedObject wraps inner in depth one-attribute objects.
func nestedObject(depth int, inner cty.Value) cty.Value {
	for range depth {
		inner = cty.ObjectVal(map[string]cty.Value{"a": inner})
	}
	return inner
}

// What the marks-walk charge accepts near the limit, cty compares within the module's time
// budget: deep lists and maps around many strings measured 260 to 310 ns per unit before the
// walk was charged markWalkWork per node (T-0116b review).
func TestAcceptedDeepComparisonsAreFast(t *testing.T) { // not parallel: it measures time
	strs := make([]cty.Value, 20_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("user-", i))
	}
	inner := cty.TupleVal(strs)
	for _, depth := range []int{25, 50, 100, 200, 400} {
		v := nestedList(depth, inner)
		other := nestedList(depth, cty.TupleVal(slices.Clone(strs)))
		cost := equalityCost(v, other, maxFunctionWork)
		if cost > maxFunctionWork {
			continue // refused
		}
		start := time.Now()
		v.Equals(other)
		if elapsed := time.Since(start); elapsed > 1500*time.Millisecond*raceSlowdown {
			t.Errorf("depth %d: cty took %v for a charge of %d", depth, elapsed, cost)
		}
	}
}

// Distinct elements that hold sets hash apart, one per bucket and side, and cty compares each
// pair with one Equals: a set of 200 objects holding small sets, typical of security group
// rules, compares as known (T-0116b review: it was refused for 86 ms of work). Sets of sets
// that collide are still refused.
func TestSetsOfSetsAreChargedByCollision(t *testing.T) {
	t.Parallel()
	rules := make([]cty.Value, 200)
	for i := range rules {
		rules[i] = cty.ObjectVal(map[string]cty.Value{
			"cidr":  cty.StringVal(fmt.Sprintf("10.0.%d.0/24", i)),
			"ports": cty.SetVal([]cty.Value{cty.NumberIntVal(80), cty.NumberIntVal(443)}),
		})
	}
	m, v := evalLocal(t, `var.r == var.r`, map[string]Variable{"r": {Name: "r", Value: cty.SetVal(rules)}})
	if !v.IsKnown() {
		t.Errorf("rules: unknown: %v", m.Diagnostics)
	}
	sets := make([]cty.Value, 20)
	for i := range sets {
		nums := make([]cty.Value, 20)
		for j := range nums {
			nums[j] = cty.NumberFloatVal(1 + float64(i*20+j)/1e15)
		}
		sets[i] = cty.SetVal(nums)
	}
	a, b := cty.SetVal(sets), cty.SetVal(sets)
	if cost := equalityCost(a, b, maxFunctionWork); cost <= maxFunctionWork {
		start := time.Now()
		a.Equals(b)
		t.Errorf("colliding sets of sets accepted at %d units; cty took %v", cost, time.Since(start))
	}
}

// setOfStringSets is a set of k distinct sets of n distinct strings.
func setOfStringSets(k, n int) cty.Value {
	sets := make([]cty.Value, k)
	for i := range sets {
		strs := make([]cty.Value, n)
		for j := range strs {
			strs[j] = cty.StringVal(fmt.Sprint("user-", i, "-", j))
		}
		sets[i] = cty.SetVal(strs)
	}
	return cty.SetVal(sets)
}

// equalityCost iterates and hashes every set it charges, each iteration sorting the set, before
// it can refuse: 30 sets of 500 strings took 4.6 s (T-0116b review). A comparison is charged
// each operand's measuring walk with its sorts (valueSizeWalk) and the estimate's own walks of
// it before the estimate runs (T-0116f).
func TestEqualityEstimateWalksAreCharged(t *testing.T) {
	t.Parallel()
	for name, v := range map[string]cty.Value{
		"sets of sets": setOfStringSets(3, 100),
		"tuples":       tupleSet(500, 4),
		"list of sets": cty.ListVal(setOfStringSets(4, 100).AsValueSlice()),
	} {
		other := cty.SetVal(slices.Clone(v.AsValueSlice())) // an equal value built apart
		if v.Type().IsListType() {
			other = cty.ListVal(slices.Clone(v.AsValueSlice()))
		}
		want := equalityCost(v, other, maxFunctionWork)
		for _, op := range []cty.Value{v, other} {
			size, sort, ok := valueSizeWalk(op, maxFunctionWork, maxFunctionWork, maxNesting)
			if !ok {
				t.Fatalf("%s: measuring refused", name)
			}
			want += (1 + equalityEstimateWalks) * (size + sort)
		}
		if got := operandsEqualityCost(v, other, maxFunctionWork); got != want || got > maxFunctionWork {
			t.Errorf("%s: cost %d, want %d within the limit", name, got, want)
		}
	}
}

// When the operands' walks alone pass the work left, the comparison is refused after measuring,
// without running equalityCost: refusing a set of 20 sets of 200 strings costs about one walk
// of it, where the estimate added about two more and then cty's comparison 1.9 s (T-0116f probe).
// A set too costly to sort with the work left is refused before it is iterated at all.
func TestComparisonsAreRefusedBeforeEstimating(t *testing.T) { // not parallel: it measures time
	v := setOfStringSets(20, 200)
	start := time.Now()
	_, sort, ok := valueSizeWalk(v, maxFunctionWork, maxFunctionWork, maxNesting)
	walk := time.Since(start)
	if !ok || 3*sort <= maxFunctionWork {
		t.Fatalf("sort %d, ok %v: want a set whose estimate walks pass the work", sort, ok)
	}
	start = time.Now()
	if cost := operandsEqualityCost(v, v, maxFunctionWork); cost <= maxFunctionWork {
		t.Errorf("accepted at %d", cost)
	}
	if elapsed := time.Since(start); elapsed > 2*walk+20*time.Millisecond*raceSlowdown {
		t.Errorf("refusing took %v; one walk takes %v", elapsed, walk)
	}
	big := tupleSet(40_000, 7)
	start = time.Now()
	if cost := operandsEqualityCost(big, big, maxFunctionWork); cost <= maxFunctionWork {
		t.Errorf("40,000 tuples accepted at %d", cost)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond*raceSlowdown {
		t.Errorf("refusing 40,000 tuples took %v; want no iteration", elapsed)
	}
}

// smallSets is a list of n sets of k distinct strings each.
func smallSets(n, k int) cty.Value {
	sets := make([]cty.Value, n)
	for i := range sets {
		elems := make([]cty.Value, k)
		for j := range elems {
			elems[j] = cty.StringVal(fmt.Sprint("v", i, "-", j))
		}
		sets[i] = cty.SetVal(elems)
	}
	return cty.ListVal(sets)
}

// cty sorts a set of a few elements in a few comparisons (sort.SliceStable insertion-sorts
// them), and a set of one element not at all, but the sort charge counted log2(n) + 1 levels
// at the full per-element work: 5,000 two-element sets were charged a third of the module's work
// for 57 ms, and 15,000 refused at about 170 ms (T-0116b review). Small sets are charged
// ceil(log2(n)) levels at smallSetSortWork, which a sweep of lists of 1,000 to 15,000 sets of one
// to four strings measured at 18 to 23 ns per unit, as large sets of strings measure 19 to 21.
func TestSmallSetComparisonsAreAccepted(t *testing.T) { // not parallel: it measures time
	l := smallSets(15_000, 2)
	other := cty.ListVal(l.AsValueSlice())
	cost := operandsEqualityCost(l, other, maxFunctionWork)
	if cost > maxFunctionWork {
		t.Fatalf("refused (%d)", cost)
	}
	start := time.Now()
	l.Equals(other)
	if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
		t.Errorf("cty took %v for a charge of %d", elapsed, cost)
	}
	// End to end, within the size limit of one local's inputs.
	m, v := evalLocal(t, `var.l == var.l`, map[string]Variable{"l": {Name: "l", Value: smallSets(2_000, 2)}})
	if !v.IsKnown() {
		t.Errorf("unknown: %v", m.Diagnostics)
	}
	// A set of one element is not sorted.
	one := newSetSort(cty.SetVal([]cty.Value{cty.StringVal("a")}))
	one.add(cty.StringVal("a"), 1)
	if one.total != 0 {
		t.Errorf("sort of one element charged %d; want 0", one.total)
	}
}

// Recalibrating small sets keeps what cty compares slowly refused: sets of small sets compare
// their elements pairwise (3,000 sets of two strings took 1.2 s in cty), and lists of small sets
// of colliding numbers compare every pair in each.
func TestSmallSetsInCostlyComparisonsAreRefused(t *testing.T) {
	t.Parallel()
	collide := make([]cty.Value, 5_000)
	for i := range collide {
		collide[i] = cty.SetVal(collidingNumberVals(4))
	}
	for name, v := range map[string]cty.Value{
		"set of small sets":               cty.SetVal(smallSets(3_000, 2).AsValueSlice()),
		"small sets of colliding numbers": cty.ListVal(collide),
	} {
		if cost := operandsEqualityCost(v, v, maxFunctionWork); cost <= maxFunctionWork {
			t.Errorf("%s: accepted (%d); want refused", name, cost)
		}
	}
}

// The small-set charge stops at smallSetSize: a set of four elements sorts over two levels at
// smallSetSortWork, one of five over three at setSortWork, and a power of two over log2(n)
// levels, where bits.Len(n) had counted one more (T-0116e review).
func TestSmallSetSortThreshold(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ n, levels, base int }{
		{2, 1, smallSetSortWork},
		{smallSetSize, 2, smallSetSortWork},
		{smallSetSize + 1, 3, setSortWork},
		{8, 3, setSortWork},
		{9, 4, setSortWork},
	} {
		elems := make([]cty.Value, tc.n)
		for i := range elems {
			elems[i] = cty.StringVal(fmt.Sprint(i))
		}
		s := newSetSort(cty.SetVal(elems))
		if s.levels != tc.levels || s.base != tc.base {
			t.Errorf("%d elements: %d levels at %d; want %d at %d", tc.n, s.levels, s.base, tc.levels, tc.base)
		}
		s.add(elems[0], 1)
		if want := (tc.base + 1) * tc.levels; s.total != want {
			t.Errorf("%d elements: one element charged %d; want %d", tc.n, s.total, want)
		}
	}
}
