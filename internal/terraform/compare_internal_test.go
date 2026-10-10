package terraform

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// contains and index compare the value with each element, and cty walks the value for marks and
// unknowns on every comparison: contains(var.t, var.t) over a 10,000-element tuple took 21 s
// (T-0114d probe). They are charged elements × the value's size, so such a call is unknown with
// a limit warning, while searching a long list for a small value stays cheap (T-0114h).
func TestContainsAndIndexAreBounded(t *testing.T) {
	t.Parallel()
	big := tupleOf(10_000, cty.StringVal("a"), cty.StringVal("b"))
	vars := map[string]Variable{"t": {Name: "t", Value: big}}
	for expr, known := range map[string]bool{
		`contains(var.t, var.t)`:   false,
		`index(var.t, var.t)`:      false,
		`contains(var.t, "b")`:     true,
		`index(var.t, "b")`:        true,
		`contains([var.t], var.t)`: true, // one comparison
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() != known {
				t.Errorf("value known %v, want %v: %v", v.IsKnown(), known, m.Diagnostics)
			}
			if limited := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }); limited == known {
				t.Errorf("function_limit reported %v, want %v: %v", limited, !known, m.Diagnostics)
			}
		})
	}
}

// nestedTuple wraps inner in depth one-element tuples.
func nestedTuple(depth int, inner cty.Value) cty.Value {
	for range depth {
		inner = cty.TupleVal([]cty.Value{inner})
	}
	return inner
}

// nestedList wraps inner in depth one-element lists.
func nestedList(depth int, inner cty.Value) cty.Value {
	for range depth {
		inner = cty.ListVal([]cty.Value{inner})
	}
	return inner
}

// Equals walks each subtree again at every level it recurses, so nested values multiply the
// work by their depth: 100 copies of a 500-deep value took 25.5 s, and one large element against
// a small 500-deep value 10 s, each charged under a quarter of the module's work (T-0114h review).
func TestNestedComparisonsAreBounded(t *testing.T) {
	t.Parallel()
	strs := func(n int, last string) cty.Value {
		elems := slices.Repeat([]cty.Value{cty.StringVal("a")}, n)
		elems[n-1] = cty.StringVal(last)
		return cty.TupleVal(elems)
	}
	copies := make([]cty.Value, 100)
	for i := range copies {
		copies[i] = nestedTuple(500, strs(1_000, fmt.Sprint(i)))
	}
	big := slices.Repeat([]cty.Value{cty.StringVal("a")}, 100_000)
	vars := map[string]Variable{
		"l":     {Name: "l", Value: cty.TupleVal(copies)},
		"v":     {Name: "v", Value: nestedTuple(500, strs(1_000, "x"))},
		"large": {Name: "large", Value: cty.ListVal([]cty.Value{nestedList(500, cty.ListVal(big))})},
		"small": {Name: "small", Value: nestedList(500, cty.ListVal([]cty.Value{cty.StringVal("a")}))},
	}
	for _, expr := range []string{
		`contains(var.l, var.v)`, `index(var.l, var.v)`,
		`contains(var.large, var.small)`, `index(var.large, var.small)`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() || !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
				t.Errorf("value known %v, diagnostics %v; want unknown with function_limit", v.IsKnown(), m.Diagnostics)
			}
		})
	}
}

// The charge holds at, just below and just above the work left: a call is evaluated when the
// module can pay for it, and unknown otherwise.
func TestComparisonChargeBoundary(t *testing.T) {
	t.Parallel()
	list := tupleOf(1_000, cty.StringVal("a"))
	val := cty.StringVal("zz")
	listSize, _ := valueSize(list, maxFunctionWork, maxNesting)
	valSize, _ := valueSize(val, maxFunctionWork, maxNesting)
	_, work := comparisonCost([]cty.Value{list, val}, []int{listSize, valSize})
	// The call also pays for its arguments and its result (a bool, one unit).
	need := listSize + valSize + work + 1
	for name, tc := range map[string]struct {
		left  int
		known bool
	}{
		"at the charge":    {need, true},
		"above the charge": {need + 1, true},
		"below the charge": {need - 1, false},
	} {
		m := &ParsedModule{fnWork: maxFunctionWork - tc.left}
		fns := m.functions(nil, nil)
		v, err := fns["contains"].Call([]cty.Value{list, val})
		if err != nil {
			t.Fatal(err)
		}
		if v.IsKnown() != tc.known {
			t.Errorf("%s: known %v, want %v", name, v.IsKnown(), tc.known)
		}
	}
}

// The charge is the elements times the value's size, plus the list's size, times the value's
// depth plus one; with sets it is at least the product of the sizes.
func TestComparisonCost(t *testing.T) {
	t.Parallel()
	list := tupleOf(100, cty.StringVal("a"))
	val := tupleOf(10, cty.StringVal("a"))
	sizes := []int{201, 21}
	// val nests one level: each comparison walks it twice (Equals at each level).
	if _, work := comparisonCost([]cty.Value{list, val}, sizes); work != (100*21+201)*2 {
		t.Errorf("work %d, want %d", work, (100*21+201)*2)
	}
	if _, work := comparisonCost([]cty.Value{list, cty.StringVal("a")}, []int{201, 2}); work != 100*2+201 {
		t.Errorf("primitive value: work %d, want %d", work, 100*2+201)
	}
	deep := nestedTuple(3, cty.StringVal("a"))
	if _, work := comparisonCost([]cty.Value{cty.TupleVal([]cty.Value{deep}), deep}, []int{5, 4}); work != (1*4+5)*4 {
		t.Errorf("depth 3: work %d, want %d", work, (1*4+5)*4)
	}
	set := cty.SetVal([]cty.Value{cty.StringVal("a")})
	if _, work := comparisonCost([]cty.Value{cty.TupleVal([]cty.Value{set}), set}, []int{4, 3}); work < 12 {
		t.Errorf("sets: work %d, want at least the product 12", work)
	}
}
