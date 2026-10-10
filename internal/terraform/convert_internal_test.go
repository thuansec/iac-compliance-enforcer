package terraform

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// largeTuple is the length from which ADR 0028 first charged tuples; the tests build sizes
// around it.
const largeTuple = 1024

// objectOf is an object of n attributes k0, k1, ... cycling through vals.
func objectOf(n int, vals ...cty.Value) cty.Value {
	attrs := make(map[string]cty.Value, n)
	for i := range n {
		attrs[fmt.Sprint("k", i)] = vals[i%len(vals)]
	}
	return cty.ObjectVal(attrs)
}

// Converting a tuple to a list or a set, or an object to a map, makes cty unify the element
// types, which is quadratic in their number: tolist over 20,000 elements took 9.8 s per local
// (T-0114c review). Function calls that convert, in their parameters or inside the call, are
// charged that cost first; over the limit they are unknown with a warning (T-0114d).
func TestConversionsOverLargeTuples(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{
		"t": tupleOf(40_000, cty.StringVal("a"), cty.StringVal("b"), cty.True),
		"s": tupleOf(40_000, cty.StringVal("a")),
		"o": objectOf(20_000, cty.StringVal("a")),
		"m": cty.MapVal(map[string]cty.Value{"a": cty.ListVal([]cty.Value{cty.StringVal("x")})}),
	})}}
	for _, expr := range []string{
		`tolist(var.c.t)`,
		`toset(var.c.t)`,
		`tomap(var.c.o)`,
		`join(",", var.c.s)`,
		`sort(var.c.s)`,
		`compact(var.c.s)`,
		`chunklist(var.c.s, 2)`,
		`zipmap(var.c.s, var.c.s)`,
		`coalesce(["x"], var.c.t)`,
		`coalesce({ x = "b" }, var.c.o)`,
		`lookup(var.c.m, "b", var.c.t)`,
		`false ? { x = "b" } : var.c.o`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			// Well under a second; converting took 2.5 to 10 s at these sizes.
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() {
				t.Errorf("value is known: %v", m.Diagnostics)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
				return d.Code == DiagFunctionLimit || d.Code == DiagExpressionTooComplex
			}) {
				t.Errorf("no limit warning: %v", m.Diagnostics)
			}
		})
	}
}

// nestedTuples is a tuple of n tuples of strings, of lengths 1,024, 1,023, ...: cty unifies
// tuples of different lengths as one list of all their element types, so the inner tuples, each
// within largeTuple, sort about n × 1,000 types together (T-0114d review: 25 s for tolist at 36).
func nestedTuples(n int) cty.Value {
	inner := make([]cty.Value, n)
	for i := range inner {
		inner[i] = tupleOf(largeTuple-i, cty.StringVal("a"))
	}
	return cty.TupleVal(inner)
}

// Tuples within largeTuple nested in one are charged their unification together, and mixed
// types the size of their comparisons.
func TestConversionsOverNestedTuples(t *testing.T) {
	t.Parallel()
	mixed := make([]cty.Value, 0, 2_049)
	for range 2_048 {
		mixed = append(mixed, tupleOf(40, cty.NumberIntVal(1)))
	}
	vars := map[string]Variable{
		"n": {Name: "n", Value: nestedTuples(36)},
		"s": {Name: "s", Value: cty.TupleVal(append(mixed, cty.StringVal("x")))},
	}
	for _, expr := range []string{
		`tolist(var.s)`, // mixed types: each pair compared element by element (2 s uncharged)
		`tolist(var.n)`,
		`toset(var.n)`,
		`coalesce(var.n, [])`,
		`join(",", flatten(var.n))`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() {
				t.Errorf("value is known: %v", m.Diagnostics)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
				t.Errorf("no limit warning: %v", m.Diagnostics)
			}
		})
	}
}

// The unification estimate follows cty: tuples of one length unify column by column, of
// different lengths all together; objects likewise by attribute names; a dynamic type ends it.
func TestUnifyWalk(t *testing.T) {
	t.Parallel()
	str := cty.String
	tup := func(n int) cty.Type { return tupleOf(n, cty.StringVal("a")).Type() }
	for name, tc := range map[string]struct {
		types []cty.Type
		want  int
	}{
		"primitives":           {[]cty.Type{str, str, str, str}, pairs(4)},
		"same-length tuples":   {[]cty.Type{tup(64), tup(64)}, pairs(2) + 64*pairs(2)},
		"different lengths":    {[]cty.Type{tup(64), tup(63)}, pairs(2) + pairs(127)},
		"lists":                {[]cty.Type{cty.List(str), cty.List(str)}, pairs(2) + pairs(2)},
		"with dynamic":         {[]cty.Type{tup(64), cty.DynamicPseudoType}, pairs(2)},
		"objects, same names":  {[]cty.Type{objectOf(8, cty.True).Type(), objectOf(8, cty.StringVal("a")).Type()}, pairs(2) + 8*pairs(2)},
		"mixed":                {append(slices.Repeat([]cty.Type{tup(64)}, 16), str), pairs(17) + pairs(17)*65},
		"objects, other names": {[]cty.Type{objectOf(80, cty.True).Type(), objectOf(79, cty.True).Type()}, pairs(2) + pairs(159)},
	} {
		w := &unifyWalk{limit: maxFunctionWork}
		w.unify(tc.types)
		if w.cost != tc.want {
			t.Errorf("%s: cost %d, want %d", name, w.cost, tc.want)
		}
	}
}

// Below the limit, calls that convert evaluate exactly as without the charge, which they pay.
func TestConversionsMatchCty(t *testing.T) {
	t.Parallel()
	mixed := tupleOf(largeTuple+100, cty.StringVal("a"), cty.True, cty.NumberIntVal(22))
	strs := tupleOf(largeTuple+100, cty.StringVal("a"), cty.StringVal("b"))
	obj := objectOf(largeTuple+100, cty.StringVal("a"), cty.NumberIntVal(1))
	vars := cty.ObjectVal(map[string]cty.Value{
		"mixed": mixed, "strs": strs, "obj": obj,
		"m": cty.MapVal(map[string]cty.Value{"a": cty.ListVal([]cty.Value{cty.StringVal("x")})}),
	})
	for _, expr := range []string{
		`tolist(var.mixed)`,
		`toset(var.strs)`,
		`tomap(var.obj)`,
		`join(",", var.strs)`,
		`sort(var.strs)`,
		`chunklist(var.mixed, 3)`,
		`coalesce(["x"], var.mixed)`,
		`coalesce({ x = 1 }, var.obj)`,
		`lookup(var.m, "b", var.strs)`,
		`false ? var.obj : { x = "b" }`,
	} {
		plain, diags := hclsyntax.ParseExpression([]byte(expr), "x.tf", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", expr, diags)
		}
		fns := map[string]function.Function{}
		for name, f := range supportedFunctions {
			fns[name] = f
		}
		want, wantDiags := plain.Value(&hcl.EvalContext{Variables: map[string]cty.Value{"var": vars}, Functions: fns})
		locals := map[string]Variable{}
		for name, v := range vars.AsValueMap() {
			locals[name] = Variable{Name: name, Value: v}
		}
		m, got := evalLocal(t, expr, locals)
		if wantDiags.HasErrors() || !got.RawEquals(want) {
			t.Errorf("%s: iace differs from cty (%v; %v)", expr, m.Diagnostics, wantDiags)
		}
		if m.fnWork < valueConversionCost(mixed, maxFunctionWork)/2 {
			t.Errorf("%s: charged %d, less than the unification", expr, m.fnWork)
		}
	}
}

// Calls that convert nothing are not charged a unification, however long their arguments.
func TestCallsThatDoNotConvertAreNotCharged(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{"t": {Name: "t", Value: tupleOf(40_000, cty.StringVal("a"), cty.True)}}
	for _, expr := range []string{`length(var.t)`, `element(var.t, 3)`, `concat(var.t, ["x"])`, `jsonencode(var.t)`} {
		m, v := evalLocal(t, expr, vars)
		if !v.IsKnown() {
			t.Errorf("%s: unknown: %v", expr, m.Diagnostics)
		}
	}
}
