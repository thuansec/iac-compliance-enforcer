package terraform

import (
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// numberAt is the number s parsed at prec bits: HCL parses literals at 512.
func numberAt(t *testing.T, s string, prec uint) cty.Value {
	t.Helper()
	f, _, err := big.ParseFloat(s, 10, prec, big.ToNearestEven)
	if err != nil {
		t.Fatal(err)
	}
	return cty.NumberVal(f)
}

// numberTuple is a tuple of n integers at prec bits, every third element replaced by the
// string "x" when mixed.
func numberTuple(t *testing.T, n int, prec uint, mixed bool) cty.Value {
	t.Helper()
	elems := make([]cty.Value, n)
	for i := range elems {
		elems[i] = numberAt(t, fmt.Sprint(i*37), prec)
		if mixed && i%3 == 2 {
			elems[i] = cty.StringVal("x")
		}
	}
	return cty.TupleVal(elems)
}

// cty converts a number to a string with exact shortest decimal formatting, which costs about
// the square of its precision whatever its value: 14 µs for 123 at 512 bits, 30 times what its
// digits were charged (T-0116c probe), and 2.4 ms at 8,192 bits. Converting numbers into string
// types is charged numberTextCost per number, and a set build pays it again for the copy it
// converts to hash (T-0124).
func TestNumberToStringConversionsAreCharged(t *testing.T) {
	t.Parallel()
	n := numberAt(t, "123", 512)
	if c := numberTextCost(n); c < 117 { // 14 µs at 120 ns per unit
		t.Errorf("numberTextCost(123 at 512 bits) = %d; want at least 117", c)
	}
	if a, b := numberTextCost(numberAt(t, "123", 2048)), numberTextCost(n); a < 10*b {
		t.Errorf("2,048 bits charged %d, 512 bits %d; want about 11 times (160 µs against 14)", a, b)
	}
	// The integer part of a large number costs its digits, faster than linearly: 1e100000
	// took 20 ms at 512 bits (T-0124 review).
	if c := numberTextCost(numberAt(t, "1e100000", 512)); c < 166_000 {
		t.Errorf("numberTextCost(1e100000) = %d; want at least 166,000 (20 ms at 120 ns per unit)", c)
	}
	for _, v := range []cty.Value{cty.Zero, cty.PositiveInfinity, cty.StringVal("1"), cty.UnknownVal(cty.Number), cty.NullVal(cty.Number)} {
		if c := numberTextCost(v); c != 0 {
			t.Errorf("numberTextCost(%#v) = %d; want 0", v, c)
		}
	}
	ints, mixed := numberTuple(t, 1_000, 512, false), numberTuple(t, 1_000, 512, true)
	per := numberTextCost(n)
	// The mixed tuple with its numbers already strings costs the same walks, unification and
	// set build, but no formatting.
	strs := make([]cty.Value, mixed.LengthInt())
	for i, e := range mixed.AsValueSlice() {
		strs[i] = e
		if e.Type() == cty.Number {
			strs[i] = cty.StringVal(e.AsBigFloat().Text('f', -1))
		}
	}
	strTuple := cty.TupleVal(strs)
	base := func(want cty.Type) int { return conversionCost(strTuple, want, maxFunctionWork) }
	for _, tc := range []struct {
		name  string
		v     cty.Value
		want  cty.Type
		least int
	}{
		{"numbers into list(string)", ints, cty.List(cty.String), 1_000 * per},
		{"numbers into set(string)", ints, cty.Set(cty.String), 2 * 1_000 * per}, // converted, then again to hash
		{"a mixed tuple into list(any)", mixed, cty.List(cty.DynamicPseudoType), base(cty.List(cty.DynamicPseudoType)) + 667*per},
		{"a mixed tuple into set(any)", mixed, cty.Set(cty.DynamicPseudoType), base(cty.Set(cty.DynamicPseudoType)) + 2*667*per},
		{"a number into string", n, cty.String, per},
		{"mixed rows", cty.TupleVal([]cty.Value{mixed}), cty.List(cty.Set(cty.DynamicPseudoType)), 2 * 667 * per},
	} {
		if c := conversionCost(tc.v, tc.want, maxFunctionWork); c < tc.least || c > maxFunctionWork {
			t.Errorf("%s: charged %d; want at least %d and accepted", tc.name, c, tc.least)
		}
	}
	// Numbers converted to numbers, and strings to strings, are not formatted.
	if c := conversionCost(ints, cty.List(cty.Number), maxFunctionWork); c >= 1_000*per {
		t.Errorf("numbers into list(number): charged %d; want less than %d", c, 1_000*per)
	}
}

// unifiedRows is a tuple of n rows [v, "a"] and one row ["b", "c"]: no row mixes numbers with
// strings at the top, but their columns unify to strings, so cty formats every v converting
// the tuple to list(any). A variable default of 100 rows of 1e-2466 took 237 ms uncharged, and
// 2.8 ms with the last row [2, "c"] (T-0124c probe).
func unifiedRows(v cty.Value, n int) cty.Value {
	rows := make([]cty.Value, 0, n+1)
	for range n {
		rows = append(rows, cty.TupleVal([]cty.Value{v, cty.StringVal("a")}))
	}
	return cty.TupleVal(append(rows, cty.TupleVal([]cty.Value{cty.StringVal("b"), cty.StringVal("c")})))
}

// boolsAndStrings is a tuple of n alternating bools and strings.
func boolsAndStrings(n int) cty.Value {
	elems := make([]cty.Value, n)
	for i := range elems {
		elems[i] = cty.True
		if i%2 == 1 {
			elems[i] = cty.StringVal("a")
		}
	}
	return cty.TupleVal(elems)
}

// Numbers that become strings only in the type the elements unify to are charged
// numberTextCost each, at any depth of that type, and once (T-0124c).
func TestNumbersUnifiedToStringsAreCharged(t *testing.T) {
	t.Parallel()
	n := numberAt(t, "1e-2466", 512) // as HCL parses the literal
	per := numberTextCost(n)
	rows := unifiedRows(n, 100)
	asObject := func(v cty.Value) cty.Value {
		attrs := map[string]cty.Value{}
		for i, e := range v.AsValueSlice() {
			attrs[fmt.Sprintf("k%d", i)] = e
		}
		return cty.ObjectVal(attrs)
	}
	// [[v], "a"] rows and [["b"], "c"]: the first column unifies to list(string).
	deep := make([]cty.Value, 0, 101)
	for _, r := range rows.AsValueSlice() {
		e := r.AsValueSlice()
		deep = append(deep, cty.TupleVal([]cty.Value{cty.TupleVal([]cty.Value{e[0]}), e[1]}))
	}
	numbersOnly := unifiedRows(n, 100).AsValueSlice()
	numbersOnly[100] = cty.TupleVal([]cty.Value{cty.NumberIntVal(2), cty.StringVal("c")})
	for _, tc := range []struct {
		name        string
		v           cty.Value
		want        cty.Type
		least, most int
	}{
		{"rows into list(any)", rows, cty.List(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		// Converted, then again to hash: 2 × 100 × per passes the limit.
		{"rows into set(any)", rows, cty.Set(cty.DynamicPseudoType), maxFunctionWork + 1, maxFunctionWork + 1},
		{"objects of rows into map(any)", asObject(rows), cty.Map(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		{"nested rows into list(any)", cty.TupleVal(deep), cty.List(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		{"rows within a list(list(any))", cty.TupleVal([]cty.Value{rows}), cty.List(cty.List(cty.DynamicPseudoType)), 100 * per, maxFunctionWork},
		// Columns that stay numbers are not formatted.
		{"number columns", cty.TupleVal(numbersOnly), cty.List(cty.DynamicPseudoType), 0, 10 * per},
		// Objects, lists and tuples unified to map(string) and list(string) (T-0124c review:
		// charged 5,152, 0 and 4,038 before, 211 to 218 ms in cty).
		{"objects beside other objects", cty.TupleVal(append(slices.Repeat([]cty.Value{cty.ObjectVal(map[string]cty.Value{"a": n})}, 100),
			cty.ObjectVal(map[string]cty.Value{"b": cty.StringVal("x")}))), cty.List(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		{"a list beside a list of strings", cty.TupleVal([]cty.Value{
			cty.ListVal(slices.Repeat([]cty.Value{n}, 100)),
			cty.ListVal([]cty.Value{cty.StringVal("x")}),
		}), cty.List(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		{"a tuple beside a list of strings", cty.TupleVal([]cty.Value{
			cty.TupleVal(slices.Repeat([]cty.Value{n}, 100)),
			cty.ListVal([]cty.Value{cty.StringVal("x")}),
		}), cty.List(cty.DynamicPseudoType), 100 * per, maxFunctionWork},
		{"maps into map(any)", cty.ObjectVal(map[string]cty.Value{
			"p": cty.MapVal(map[string]cty.Value{"k": n}),
			"q": cty.MapVal(map[string]cty.Value{"k": cty.StringVal("x")}),
		}), cty.Map(cty.DynamicPseudoType), per, maxFunctionWork},
		// An unknown element unifies to the dynamic type: cty formats nothing.
		{"rows beside an unknown", cty.TupleVal(append(rows.AsValueSlice(), cty.DynamicVal)), cty.List(cty.DynamicPseudoType), 0, per},
	} {
		if c := conversionCost(tc.v, tc.want, maxFunctionWork); c < tc.least || c > tc.most {
			t.Errorf("%s: charged %d; want %d to %d", tc.name, c, tc.least, tc.most)
		}
	}
	// A map beside objects is converted to an object when unifying them as maps fails
	// (unifyObjectsAsMaps): a bool beside a number one level down is enough. Its numbers under
	// a string are formatted, and only toText's map-to-object branch charges them (T-0124f
	// review: 74,243 units for one such map with the branch, 0 without; cty's conversion
	// succeeds).
	nested := cty.ObjectVal(map[string]cty.Value{
		"a": cty.ObjectVal(map[string]cty.Value{"x": cty.True, "s": cty.TupleVal([]cty.Value{cty.StringVal("t")})}),
		"b": cty.ObjectVal(map[string]cty.Value{"y": cty.NumberIntVal(1)}),
	})
	e := cty.ObjectVal(map[string]cty.Value{"x": cty.StringVal("true"), "s": cty.TupleVal([]cty.Value{n}), "y": cty.StringVal("2")})
	maps := []cty.Value{nested}
	for range 100 {
		maps = append(maps, cty.MapVal(map[string]cty.Value{"a": e, "b": e}))
	}
	beside := cty.TupleVal(maps)
	if u, _ := convert.UnifyUnsafe(elementTypes(beside)); !u.IsObjectType() || typeHasSet(u) {
		t.Fatalf("maps beside an object unify to %#v; want an object without sets", u)
	}
	if _, err := convert.Convert(beside, cty.List(cty.DynamicPseudoType)); err != nil {
		t.Fatalf("cty does not convert maps beside an object: %v", err)
	}
	if c := conversionCost(beside, cty.List(cty.DynamicPseudoType), maxFunctionWork); c < 100*per || c > maxFunctionWork {
		t.Errorf("maps converted to an object: charged %d; want %d to %d", c, 100*per, maxFunctionWork)
	}
	// With a set in the unified type, convert charges the map instead (its (object or map) to
	// object case); cty's conversion of this one then fails on "x".
	obj := cty.ObjectVal(map[string]cty.Value{
		"a": cty.TupleVal([]cty.Value{cty.StringVal("s"), cty.True}),
		"b": cty.SetVal([]cty.Value{cty.NumberIntVal(1)}),
	})
	row := cty.TupleVal([]cty.Value{n, cty.StringVal("x")})
	pair := cty.TupleVal([]cty.Value{obj, cty.MapVal(map[string]cty.Value{"a": row, "b": row})})
	if u, _ := convert.UnifyUnsafe(elementTypes(pair)); !u.IsObjectType() || !typeHasSet(u) {
		t.Fatalf("a map beside an object with a set unifies to %#v; want an object with a set", u)
	}
	if c := conversionCost(pair, cty.List(cty.DynamicPseudoType), maxFunctionWork); c < per || c > maxFunctionWork {
		t.Errorf("a map converted to an object with a set: charged %d; want %d to %d", c, per, maxFunctionWork)
	}
	// toText itself charges only the attributes the object type names.
	w := &unifyWalk{limit: maxFunctionWork}
	w.toText(cty.MapVal(map[string]cty.Value{"a": n, "b": n}), cty.Object(map[string]cty.Type{"a": cty.String}))
	if w.cost != per {
		t.Errorf("toText of a map to an object: charged %d; want %d (attribute a only)", w.cost, per)
	}
	// 1,000 rows do not fit.
	if c := conversionCost(unifiedRows(n, 1_000), cty.List(cty.DynamicPseudoType), maxFunctionWork); c <= maxFunctionWork {
		t.Errorf("1,000 rows into list(any): charged %d; want refused", c)
	}
}

// What the charge accepts converts quickly: a timing sweep of tuples of 100 to 4,000 integers,
// fractions and mixed values at 512, 2,048 and 8,192 bits, into list(string), set(string),
// list(any) and set(any), measured 18 to 80 ns per unit (T-0124).
func TestAcceptedNumberConversionsAreFast(t *testing.T) { // not parallel: it measures time
	for _, tc := range []struct {
		v    cty.Value
		want cty.Type
		// estimate, when set, bounds the estimate alone.
		estimate time.Duration
	}{
		{numberTuple(t, 4_000, 512, false), cty.List(cty.String), 0},
		{numberTuple(t, 4_000, 512, true), cty.Set(cty.DynamicPseudoType), 0},
		{numberTuple(t, 1_000, 2_048, false), cty.List(cty.String), 0},
		{numberTuple(t, 100, 8_192, false), cty.List(cty.String), 0},
		// Rows whose columns unify to strings (T-0124c).
		{unifiedRows(numberAt(t, "1e-2466", 512), 100), cty.List(cty.DynamicPseudoType), 0},
		{unifiedRows(numberAt(t, "123", 512), 2_000), cty.List(cty.DynamicPseudoType), 0},
		// No numbers: the estimate does not unify them again (T-0124c review: 378 ms).
		{boolsAndStrings(6_500), cty.List(cty.DynamicPseudoType), 50 * time.Millisecond},
	} {
		// The estimate is timed with the conversion: it can unify too (T-0124c review).
		start := time.Now()
		cost := conversionCost(tc.v, tc.want, maxFunctionWork)
		if e := time.Since(start); tc.estimate > 0 && e > tc.estimate*raceSlowdown {
			t.Errorf("%d elements into %s: the estimate took %v", tc.v.LengthInt(), tc.want.FriendlyName(), e)
		}
		if cost > maxFunctionWork {
			t.Errorf("%d elements into %s: refused", tc.v.LengthInt(), tc.want.FriendlyName())
			continue
		}
		if _, err := convert.Convert(tc.v, tc.want); err != nil {
			t.Fatal(err)
		}
		// The limit's worth of work at 120 ns per unit is about 1 s.
		if elapsed := time.Since(start); elapsed > time.Duration(cost)*120*time.Nanosecond*raceSlowdown+50*time.Millisecond {
			t.Errorf("%d elements into %s: cty took %v for a charge of %d", tc.v.LengthInt(), tc.want.FriendlyName(), elapsed, cost)
		}
	}
}

// A number passed to a string parameter is formatted when cty converts the argument.
func TestNumberArgumentsToStringsAreCharged(t *testing.T) {
	t.Parallel()
	n := numberAt(t, "123", 8_192)
	m, v := evalLocal(t, `upper(var.n)`, map[string]Variable{"n": {Name: "n", Value: n}})
	if !v.IsKnown() {
		t.Fatalf("unknown: %v", m.Diagnostics)
	}
	if m.fnWork < numberTextCost(n) {
		t.Errorf("function work %d; want at least the formatting, %d", m.fnWork, numberTextCost(n))
	}
}
