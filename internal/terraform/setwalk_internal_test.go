package terraform

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// tupleSet is a set of n distinct tuples of width short strings, small enough for the size
// limits: a unique first string, then "a".
func tupleSet(n, width int) cty.Value {
	elems := make([]cty.Value, n)
	for i := range elems {
		row := make([]cty.Value, width)
		row[0] = cty.StringVal(fmt.Sprint(i))
		for j := 1; j < width; j++ {
			row[j] = cty.StringVal("a")
		}
		elems[i] = cty.TupleVal(row)
	}
	return cty.SetVal(elems)
}

// cty sorts a set every time it is iterated, hashing both sides of each comparison when the
// elements are compound, so walking a set of 8,000 seven-string tuples costs far more than its
// size: six `length(var.s)` locals took 14.4 s, each measuring its argument for free (T-0114k
// review). Measuring a set charges its sort, so the locals stop at the module's work.
func TestWalkingCompoundSetsIsCharged(t *testing.T) { // not parallel: it measures time
	s := tupleSet(8_000, 7)
	var src strings.Builder
	src.WriteString("locals {\n")
	for i := range 6 {
		fmt.Fprintf(&src, "  n%d = length(var.s)\n", i)
	}
	src.WriteString("}\n")
	m := parseLocalsModule(t, src.String())
	start := time.Now()
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{"s": {Name: "s", Value: s}})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	known := 0
	for _, l := range locals {
		if l.Value.IsKnown() {
			known++
		}
	}
	if known == len(locals) {
		t.Errorf("all %d locals known; want the walks charged until the work runs out", known)
	}
}

// Measuring a set too costly to sort refuses it before iterating, since iterating is what
// sorts: one iteration of 12,000 tuples took 0.69 s (T-0114k review).
func TestMeasuringRefusesSetsTooCostlyToSort(t *testing.T) {
	t.Parallel()
	s := tupleSet(40_000, 7)
	start := time.Now()
	if _, _, ok := valueSizeWalk(s, maxFunctionWork, maxFunctionWork, maxNesting); ok {
		t.Error("measured; want refused")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond*raceSlowdown {
		t.Errorf("refusing took %v; want no iteration", elapsed)
	}
	// The estimate is checked against the work the caller has left, and a refusal reports a
	// size past the limit, so callers reading only the size treat it as too large.
	small := tupleSet(100, 2)
	if size, sort, ok := valueSizeWalk(small, 1_000_000, 100, maxNesting); ok || size <= 1_000_000 || sort <= 100 {
		t.Errorf("size %d, sort %d, ok %v with 100 work left; want refused past both limits", size, sort, ok)
	}
	if _, sort, ok := valueSizeWalk(small, 1_000_000, maxFunctionWork, maxNesting); !ok || sort == 0 {
		t.Errorf("sort %d, ok %v with all the work left; want measured and its sort charged", sort, ok)
	}
}

// An ordinary set stays cheap: a set of 1,000 strings is charged its sort, a small part of the
// module's work, and its size is unchanged.
func TestOrdinarySetWalksAreCheap(t *testing.T) {
	t.Parallel()
	strs := make([]cty.Value, 1_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("10.0.", i, ".0/24"))
	}
	s := cty.SetVal(strs)
	size, sort, ok := valueSizeWalk(s, maxFunctionWork, maxFunctionWork, maxNesting)
	plain, _ := valueSize(s, maxFunctionWork, maxNesting)
	if !ok || size != plain || sort == 0 || sort > maxFunctionWork/50 {
		t.Errorf("size %d (plain %d), sort %d, ok %v; want the plain size and a small sort charge", size, plain, sort, ok)
	}
	m, v := evalLocal(t, `length(var.s)`, map[string]Variable{"s": {Name: "s", Value: s}})
	if !v.IsKnown() {
		t.Errorf("length unknown: %v", m.Diagnostics)
	}
}

// A for expression walks its collection twice, measuring it and iterating it, and each walk of a
// set sorts it: one iteration of 12,000 tuples took 0.69 s (T-0114k review), and three loops
// over it took 4.4 s. The sorts are charged, so the loops stop at the module's work, and a
// set too costly to sort with the work left is refused before it is walked again.
func TestForExpressionsOverSetsAreCharged(t *testing.T) { // not parallel: it measures time
	// A quarter of the work and of the set, to keep the test short under -race (T-0125).
	vars := map[string]Variable{"s": {Name: "s", Value: tupleSet(3_000, 7)}}
	m := parseLocalsModule(t, `locals {
  a = [for x in var.s : x[0]]
  b = [for x in var.s : x[1]]
  c = [for x in var.s : x[2]]
}
`)
	m.fnWork = maxFunctionWork * 3 / 4
	start := time.Now()
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	// The work left, plus the uncharged marks walk of the inputs (T-0116f).
	if elapsed := time.Since(start); elapsed > 800*time.Millisecond*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	for name, l := range locals {
		if l.Value.IsKnown() {
			t.Errorf("local.%s known; want the loops charged until the work runs out", name)
		}
	}
	// A loop over an ordinary set stays known.
	strs := make([]cty.Value, 1_000)
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("10.0.", i, ".0/24"))
	}
	if _, v := evalLocal(t, `[for x in var.s : upper(x)]`, map[string]Variable{"s": {Name: "s", Value: cty.SetVal(strs)}}); !v.IsKnown() {
		t.Error("loop over 1,000 strings unknown")
	}
}

// cty compares numbers that are not integers by their exact decimal text, so sorting a set of
// them costs several times a set of integers: a set of 8,000 halves took 243 ms to walk, charged
// at 640 ns per unit before nonIntegerSortWork. Walking 1,000 halves takes 3.4 times as long as
// 1,000 integers, both near 80 ns per unit since integers have their own sort base (T-0116e).
func TestSortingNonIntegersIsCharged(t *testing.T) {
	t.Parallel()
	halves, ints := make([]cty.Value, 1_000), make([]cty.Value, 1_000)
	for i := range halves {
		halves[i] = cty.NumberFloatVal(float64(i) + 0.5)
		ints[i] = cty.NumberIntVal(int64(i) * 10)
	}
	_, intSort, _ := valueSizeWalk(cty.SetVal(ints), maxFunctionWork, maxFunctionWork, maxNesting)
	_, halfSort, _ := valueSizeWalk(cty.SetVal(halves), maxFunctionWork, maxFunctionWork, maxNesting)
	if halfSort < 3*intSort {
		t.Errorf("sorting halves charged %d, integers %d; want at least three times", halfSort, intSort)
	}
}

// A local whose value is refused for its sort spends the walk it did, so the next local is
// refused before it iterates the set again: ten copies of a set of 6,000 tuples took 16.9 s when
// a refusal spent nothing (T-0116d review).
func TestRefusedLocalsSpendTheirSorts(t *testing.T) { // not parallel: it measures time
	var src strings.Builder
	src.WriteString("locals {\n")
	for i := range 10 {
		fmt.Fprintf(&src, "  a%d = var.s\n", i)
	}
	src.WriteString("}\n")
	m := parseLocalsModule(t, src.String())
	// A quarter of the work and of the set, to keep the test short under -race (T-0125).
	m.fnWork = maxFunctionWork * 3 / 4
	vars := map[string]Variable{"s": {Name: "s", Value: tupleSet(1_500, 7)}}
	start := time.Now()
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	// Measuring var.s, the locals that fit, and one refused after its walk.
	if elapsed := time.Since(start); elapsed > time.Second*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	if m.fnWork < maxFunctionWork {
		t.Errorf("work %d spent; want all of it", m.fnWork)
	}
	known := 0
	for _, l := range locals {
		if l.Value.IsKnown() {
			known++
		}
	}
	if known > 2 {
		t.Errorf("%d locals known; want the rest refused once the work is spent", known)
	}
}

// Each charge site pays a set's sort, which a tuple of the same elements does not have.
func TestMeasuringChargesSorts(t *testing.T) {
	t.Parallel()
	set := tupleSet(500, 3)
	tuple := cty.TupleVal(set.AsValueSlice())
	_, sort, _ := valueSizeWalk(set, maxFunctionWork, maxFunctionWork, maxNesting)
	if sort == 0 {
		t.Fatal("no sort counted")
	}
	// A call measures its arguments, and cty walks them for marks before calling: twice.
	call := func(v cty.Value) int {
		m := &ParsedModule{}
		if _, err := m.functions(nil, nil)["length"].Call([]cty.Value{v}); err != nil {
			t.Fatal(err)
		}
		return m.fnWork
	}
	if got := call(set) - call(tuple); got < 2*sort {
		t.Errorf("call charged %d more for the set; want at least twice its sort %d", got, sort)
	}
	// A refused measurement spends what it walked, here the work left.
	m := &ParsedModule{fnWork: maxFunctionWork - 1_000}
	if _, err := m.functions(nil, nil)["length"].Call([]cty.Value{tupleSet(2_000, 7)}); err != nil {
		t.Fatal(err)
	}
	if m.fnWork != maxFunctionWork {
		t.Errorf("refused call left %d work; want none", maxFunctionWork-m.fnWork)
	}
	// The locals estimate: a path into a variable, and a whole variable.
	vars := func(v cty.Value) map[string]Variable {
		return map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{"s": v})}}
	}
	for _, expr := range []string{`var.c.s != null`, `var.c != null`} {
		ms, _ := evalLocal(t, expr, vars(set))
		mt, _ := evalLocal(t, expr, vars(tuple))
		if got := ms.fnWork - mt.fnWork; got < sort {
			t.Errorf("%s: charged %d more for the set; want at least its sort %d", expr, got, sort)
		}
	}
}

// A set's elements that hold sets are hashed on every comparison of its sort, which sorts the
// sets inside them again: a set of 100 sets of 200 strings took 13.5 s to measure when only
// each inner sort was charged, once (T-0116d review).
func TestNestedSetSortsAreCharged(t *testing.T) {
	t.Parallel()
	outer := make([]cty.Value, 200)
	for i := range outer {
		inner := make([]cty.Value, 8)
		for j := range inner {
			inner[j] = cty.StringVal(fmt.Sprint(i, "-", j))
		}
		outer[i] = cty.SetVal(inner)
	}
	_, nested, _ := valueSizeWalk(cty.SetVal(outer), maxFunctionWork, maxFunctionWork, maxNesting)
	_, inners, _ := valueSizeWalk(cty.TupleVal(outer), maxFunctionWork, maxFunctionWork, maxNesting)
	levels := 8 // log2(200), rounded up
	// Each level of the outer sort sorts every inner set at least twice, once per side.
	if nested < inners*2*levels {
		t.Errorf("nested sort %d; want at least the inner sorts %d, twice per level of %d", nested, inners, levels)
	}
}

// numberTupleSet is a set of n distinct seven-number tuples.
func numberTupleSet(n int) cty.Value {
	elems := make([]cty.Value, n)
	for i := range elems {
		row := make([]cty.Value, 7)
		row[0] = cty.NumberIntVal(int64(i))
		for j := 1; j < len(row); j++ {
			row[j] = cty.NumberIntVal(int64(j))
		}
		elems[i] = cty.TupleVal(row)
	}
	return cty.SetVal(elems)
}

// The measuring walk reports marks as ContainsMarked does, wherever they are, and a walk that
// stops before the end reports marked (fail closed), since it did not see the rest.
func TestMeasuringReportsMarks(t *testing.T) {
	t.Parallel()
	secret := cty.StringVal("x").Mark(SensitiveMark)
	for name, tc := range map[string]struct {
		v      cty.Value
		limit  int
		marked bool
	}{
		"plain":            {cty.ListVal([]cty.Value{cty.StringVal("a")}), 100, false},
		"deep in a list":   {cty.ObjectVal(map[string]cty.Value{"l": cty.ListVal([]cty.Value{cty.StringVal("a"), secret})}), 100, true},
		"in a set":         {cty.TupleVal([]cty.Value{cty.SetVal([]cty.Value{secret, cty.StringVal("b")})}), 100, true},
		"marked unknown":   {cty.UnknownVal(cty.String).Mark(SensitiveMark), 100, true},
		"map value":        {cty.MapVal(map[string]cty.Value{"k": secret}), 100, true},
		"stopped":          {tupleOf(50, cty.StringVal("a")), 10, true},
		"plain set":        {tupleSet(100, 3), maxFunctionWork, false},
		"plain set, short": {tupleSet(100, 3), 10, true},
	} {
		_, _, marked, _ := valueMarksWalk(tc.v, tc.limit, maxFunctionWork, maxNesting)
		if marked != tc.marked {
			t.Errorf("%s: marked %v, want %v", name, marked, tc.marked)
		}
		if _, _, ok := valueSizeWalk(tc.v, tc.limit, maxFunctionWork, maxNesting); ok && marked != tc.v.ContainsMarked() {
			t.Errorf("%s: marked %v, ContainsMarked %v", name, marked, tc.v.ContainsMarked())
		}
	}
}

// A local whose input is sensitive stays sensitive when its call is refused: the locals estimate
// takes the input's marks from measuring it (inputsSensitive).
func TestRefusedLocalsKeepTheirInputsMarks(t *testing.T) {
	t.Parallel()
	s := tupleSet(12_000, 7) // measured by the local, too costly to walk for the call
	for _, sensitive := range []bool{false, true} {
		v := s
		if sensitive {
			v = s.Mark(SensitiveMark)
		}
		m, got := evalLocal(t, `length(var.s)`, map[string]Variable{"s": {Name: "s", Value: v}})
		if got.IsKnown() || got.IsMarked() != sensitive {
			t.Errorf("sensitive %v: got known %v, marked %v: %v", sensitive, got.IsKnown(), got.IsMarked(), m.Diagnostics)
		}
		if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
			t.Errorf("sensitive %v: the call was not refused: %v", sensitive, m.Diagnostics)
		}
	}
}

// A refused call's unknown result takes its arguments' marks from measuring them, for
// functions that accept marked arguments (cty marks the others' results itself), whether
// measuring stopped or the call was not affordable. An argument too large to measure may hold a
// mark measuring did not reach, so the result is marked (fail closed).
func TestRefusedCallsKeepTheirArgumentsMarks(t *testing.T) {
	t.Parallel()
	plain := tupleOf(1_000, cty.StringVal("a"))
	for name, tc := range map[string]struct {
		left   int
		arg    cty.Value
		marked bool
	}{
		"not measured, sensitive":   {10, plain.Mark(SensitiveMark), true},
		"not measured, plain":       {10, plain, true},
		"not affordable, sensitive": {3_000, plain.Mark(SensitiveMark), true},
		"not affordable, deep mark": {3_000, tupleOf(999, cty.StringVal("a"), cty.StringVal("x").Mark(SensitiveMark)), true},
		"not affordable, plain":     {3_000, plain, false},
	} {
		for _, fn := range []string{"concat", "reverse"} {
			m := &ParsedModule{fnWork: maxFunctionWork - tc.left}
			got, err := m.functions(nil, nil)[fn].Call([]cty.Value{tc.arg})
			if err != nil {
				t.Fatalf("%s, %s: %v", name, fn, err)
			}
			if got.IsKnown() || !m.fnLimited || got.IsMarked() != tc.marked {
				t.Errorf("%s, %s: known %v, limited %v, marked %v; want a refused unknown, marked %v",
					name, fn, got.IsKnown(), m.fnLimited, got.IsMarked(), tc.marked)
			}
		}
	}
}

// Whether a local's inputs are sensitive, and whether a refused call's arguments are, was a
// ContainsMarked walk of each, sorting every set in it again without a charge: three locals
// `length(true ? var.t : toset([["a", …, "g"]]))` over a set of 12,000 tuples of numbers took
// 1.8 s after T-0116d, about two walks of the set (one of them that check). Both now come from
// the measurements made anyway, so the locals cost about one walk (T-0116g).
func TestMarksChecksDoNotWalkAgain(t *testing.T) { // not parallel: it measures time
	s := numberTupleSet(12_000)
	start := time.Now()
	_, _, _ = valueSizeWalk(s, maxFunctionWork, maxFunctionWork, maxNesting)
	walk := time.Since(start)
	const local = `length(true ? var.t : toset([["a", "b", "c", "d", "e", "f", "g"]]))`
	m := parseLocalsModule(t, "locals {\n  a = "+local+"\n  b = "+local+"\n  c = "+local+"\n}\n")
	start = time.Now()
	if _, err := m.EvaluateLocals(context.Background(), map[string]Variable{"t": {Name: "t", Value: s}}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > walk*3/2+100*time.Millisecond*raceSlowdown {
		t.Errorf("took %v; one walk of the set takes %v", elapsed, walk)
	}
}

// A local refused as too large, before or after it is evaluated, is marked exactly when its
// inputs are: secrets reach a local only through the variables, module values and locals it
// uses, which inputsSensitive checks (iace marks only sensitive variables and module outputs;
// a refused call's fail-closed mark adds nothing over inputs found unmarked). A mark deep inside
// an input marks the unknown; plain inputs leave it unmarked (T-0116j). Once sensitive() is
// evaluated, a local calling it must be marked too (T-0126).
func TestTooLargeLocalsAreMarkedByTheirInputs(t *testing.T) {
	t.Parallel()
	deep := cty.TupleVal([]cty.Value{cty.StringVal("abcdefghabcdefgh"), cty.StringVal("x").Mark(SensitiveMark)})
	plain := cty.TupleVal([]cty.Value{cty.StringVal("abcdefghabcdefgh"), cty.StringVal("x")})
	for name, tc := range map[string]struct {
		src       string // locals, the last of which, "v", is too large
		marked    bool
		evaluated bool // refused after evaluation, not by its estimate
	}{
		"evaluated, sensitive":     {`v = [for i in range(1000) : [for j in range(20) : var.d]]`, true, true},
		"evaluated, plain":         {`v = [for i in range(1000) : [for j in range(20) : var.p]]`, false, true},
		"evaluated, through local": {"a = var.d\n  v = [for i in range(1000) : [for j in range(20) : local.a]]", true, true},
		"estimated, sensitive":     {`v = [var.t, var.t, var.st]`, true, false},
		"estimated, plain":         {`v = [var.t, var.t, var.t]`, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tup := tupleOf(10_000, cty.StringVal("abcdefgh"))
			elems := tup.AsValueSlice()
			elems[0] = elems[0].Mark(SensitiveMark) // a mark deep in a large input
			m := parseLocalsModule(t, "locals {\n  "+tc.src+"\n}\n")
			locals, err := m.EvaluateLocals(t.Context(), map[string]Variable{
				"d": {Name: "d", Value: deep}, "p": {Name: "p", Value: plain},
				"t": {Name: "t", Value: tup}, "st": {Name: "st", Value: cty.TupleVal(elems)},
			})
			if err != nil {
				t.Fatal(err)
			}
			v := locals["v"].Value
			if v.IsKnown() || v.IsMarked() != tc.marked {
				t.Errorf("known %v, marked %v; want unknown, marked %v: %v", v.IsKnown(), v.IsMarked(), tc.marked, m.Diagnostics)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Local value too large" }) {
				t.Errorf("not refused as too large: %v", m.Diagnostics)
			}
			// Evaluating spends function work (range, the for expressions); a refusal by the
			// estimate spends none on these inputs, which hold no sets.
			if evaluated := m.fnWork > 0; evaluated != tc.evaluated {
				t.Errorf("evaluated %v (work %d), want %v: the case no longer takes its refusal path", evaluated, m.fnWork, tc.evaluated)
			}
		})
	}
}

// cty sorts numbers by comparing them as big.Float values, which costs about twice comparing
// strings: a sweep of sets of 1,000 to 8,000 integers measured about 150 ns per unit of the walk
// charge, as strings measured 56 to 67 (T-0116d, T-0116e sweep). Numbers have their own sort base, so a set of
// integers is charged more than a set of as many longer strings (73 to 82 ns per unit, T-0116e).
func TestSortingIntegersIsCharged(t *testing.T) {
	t.Parallel()
	ints := make([]cty.Value, 4_000)
	strs := make([]cty.Value, 4_000)
	for i := range ints {
		ints[i] = cty.NumberIntVal(int64(i * 7_919))
		strs[i] = cty.StringVal(fmt.Sprint("10.0.", i, ".0/24"))
	}
	_, intSort, ok := valueSizeWalk(cty.SetVal(ints), maxFunctionWork, maxFunctionWork, maxNesting)
	_, strSort, ok2 := valueSizeWalk(cty.SetVal(strs), maxFunctionWork, maxFunctionWork, maxNesting)
	if !ok || !ok2 || intSort <= strSort {
		t.Errorf("integers sort for %d, strings for %d (ok %v, %v); want the integers charged more", intSort, strSort, ok, ok2)
	}
	if got, want := elementSortFloor(cty.Number, maxFunctionWork), numberSortWork; got != want {
		t.Errorf("number sort floor %d; want %d", got, want)
	}
}
