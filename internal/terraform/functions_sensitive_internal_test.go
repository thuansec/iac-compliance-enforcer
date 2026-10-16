package terraform

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// sensitive(x) is x marked sensitive, and nonsensitive(x) is x without the mark on x itself,
// as in Terraform: nonsensitive of a value that is not sensitive returns it unchanged (Terraform's
// implementation returns no error, though its documentation's example still shows one), and
// marks nested inside x stay. Neither is an unsupported function (T-0126).
func TestSensitiveFunctions(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"s": {Name: "s", Value: cty.StringVal("fake-token").Mark(SensitiveMark)},
		"u": {Name: "u", Value: cty.UnknownVal(cty.String)},
	}
	for expr, want := range map[string]cty.Value{
		`sensitive("x")`:                 cty.StringVal("x").Mark(SensitiveMark),
		`core::sensitive("x")`:           cty.StringVal("x").Mark(SensitiveMark),
		`sensitive(var.s)`:               cty.StringVal("fake-token").Mark(SensitiveMark),
		`sensitive(var.u)`:               cty.UnknownVal(cty.String).Mark(SensitiveMark),
		`sensitive([1, 2])`:              cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}).Mark(SensitiveMark),
		`nonsensitive(var.s)`:            cty.StringVal("fake-token"),
		`nonsensitive("plain")`:          cty.StringVal("plain"),
		`nonsensitive(sensitive(var.u))`: cty.UnknownVal(cty.String),
		`nonsensitive([var.s])`:          cty.TupleVal([]cty.Value{cty.StringVal("fake-token").Mark(SensitiveMark)}),
		`length(sensitive([1, 2]))`:      cty.NumberIntVal(2).Mark(SensitiveMark),
	} {
		m, got := evalLocal(t, expr, vars)
		if !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", expr, got, want)
		}
		if len(m.Diagnostics) != 0 {
			t.Errorf("%s: diagnostics %v", expr, m.Diagnostics)
		}
	}
}

// cty walks a mark function's argument for marks before each call, sorting every set in it,
// and checks the result's type: 400 nested nonsensitive calls over a tuple of 100,000 elements
// took 9.3 s uncharged (T-0126 review). Each call is charged those walks, so a chain is refused
// within about the function work's time, and a refused sensitive() is still marked.
func TestMarkFunctionChainsAreBounded(t *testing.T) { // not parallel: it measures time
	elems := make([]cty.Value, 100_000)
	strs := make([]cty.Value, 2_000)
	for i := range elems {
		elems[i] = cty.StringVal("x")
	}
	for i := range strs {
		strs[i] = cty.StringVal(fmt.Sprint("10.0.", i, ".0/24"))
	}
	vars := map[string]Variable{
		"b": {Name: "b", Value: cty.TupleVal(elems)},
		"s": {Name: "s", Value: cty.SetVal(strs)},
	}
	chain := func(fn, arg string) string {
		return "length(" + strings.Repeat(fn+"(", 400) + arg + strings.Repeat(")", 401)
	}
	for _, tc := range []struct {
		expr   string
		marked bool
	}{
		{chain("nonsensitive", "var.b"), false},
		{chain("sensitive", "var.b"), true},
		{chain("nonsensitive", "var.s"), false},
		{chain("sensitive", "var.s"), true},
	} {
		start := time.Now()
		m, v := evalLocal(t, tc.expr, vars)
		elapsed := time.Since(start)
		name := tc.expr[:30]
		if v.IsKnown() || !hasDiagnostic(m, "Function call too large") {
			t.Errorf("%s: known %v, diagnostics %v; want refused", name, v.IsKnown(), m.Diagnostics)
		}
		if tc.marked && !v.HasMark(SensitiveMark) {
			t.Errorf("%s: %#v; want a refused sensitive() marked", name, v)
		}
		// The limit's worth of work is about 1 s at 120 ns per unit.
		if elapsed > 2*time.Second*raceSlowdown {
			t.Errorf("%s: took %v", name, elapsed)
		}
	}
}
