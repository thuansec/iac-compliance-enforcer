package terraform

import (
	"fmt"
	"math/big"
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

// What the charge accepts converts quickly: a timing sweep of tuples of 100 to 4,000 integers,
// fractions and mixed values at 512, 2,048 and 8,192 bits, into list(string), set(string),
// list(any) and set(any), measured 18 to 80 ns per unit (T-0124).
func TestAcceptedNumberConversionsAreFast(t *testing.T) { // not parallel: it measures time
	for _, tc := range []struct {
		v    cty.Value
		want cty.Type
	}{
		{numberTuple(t, 4_000, 512, false), cty.List(cty.String)},
		{numberTuple(t, 4_000, 512, true), cty.Set(cty.DynamicPseudoType)},
		{numberTuple(t, 1_000, 2_048, false), cty.List(cty.String)},
		{numberTuple(t, 100, 8_192, false), cty.List(cty.String)},
	} {
		cost := conversionCost(tc.v, tc.want, maxFunctionWork)
		if cost > maxFunctionWork {
			t.Errorf("%d elements into %s: refused", tc.v.LengthInt(), tc.want.FriendlyName())
			continue
		}
		start := time.Now()
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
