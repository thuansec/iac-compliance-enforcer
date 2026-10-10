package terraform

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// tupleOf is a tuple of n elements cycling through vals.
func tupleOf(n int, vals ...cty.Value) cty.Value {
	elems := make([]cty.Value, n)
	for i := range elems {
		elems[i] = vals[i%len(vals)]
	}
	return cty.TupleVal(elems)
}

// A conditional whose results have different types makes cty unify them, and unifying a tuple
// type is quadratic in its length: one local over 20,000 elements took 2.5 s (40,000: 11 s).
// The conditional is charged that cost first; over the limit hcl does not unify, the false
// result is unknown, and a warning says so (T-0114c, ADR 0030).
func TestConditionalsOverLargeTuples(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{
		"same":  tupleOf(40_000, cty.StringVal("a")),
		"mixed": tupleOf(40_000, cty.StringVal("a"), cty.NumberIntVal(1)),
	})}}
	for name, tc := range map[string]struct {
		expr  string
		known bool
	}{
		// Refused, the expression is unknown, whichever result is taken.
		"same, true":   {`true ? var.c.same : ["x"]`, false},
		"same, false":  {`false ? ["x"] : var.c.same`, false},
		"mixed, true":  {`true ? var.c.mixed : ["x"]`, false},
		"mixed, false": {`false ? ["x"] : var.c.mixed`, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, tc.expr, vars)
			// About 50 ms; unifying took over 10 s at this length.
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() != tc.known {
				t.Errorf("value known %v, want %v: %v", v.IsKnown(), tc.known, m.Diagnostics)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Conditional too large" }) {
				t.Errorf("no limit warning: %v", m.Diagnostics)
			}
		})
	}
}

// Conditionals evaluate exactly as hcl evaluates them, values, types and diagnostics: only the
// taken result's errors count, none when the condition is unknown, and try sees them; a tuple
// result is not converted. (A first version reported every result's errors and converted tuples
// to lists, which turned Terraform's guard idioms unknown; T-0114c review.)
func TestConditionalsMatchHCL(t *testing.T) {
	t.Parallel()
	mixed := tupleOf(1124, cty.StringVal("a"), cty.NumberIntVal(22))
	vars := cty.ObjectVal(map[string]cty.Value{
		"x":     cty.NullVal(cty.Object(map[string]cty.Type{"name": cty.String})),
		"l":     cty.ListValEmpty(cty.String),
		"o":     cty.ObjectVal(map[string]cty.Value{"a": cty.True}),
		"c":     cty.UnknownVal(cty.Bool),
		"mixed": mixed,
	})
	for _, expr := range []string{
		`var.x == null ? "none" : var.x.name`,
		`length(var.l) > 0 ? var.l[0] : "none"`,
		`try(true ? var.o.missing : "a", "fallback")`,
		`var.c ? var.o.missing : "a"`,
		`true ? var.mixed : null`,
		`true ? var.mixed : var.mixed`,
		`var.c ? var.mixed : var.mixed`,
		`true ? var.mixed : ["x"]`,
		`"%{ if var.x == null }none%{ else }${var.x.name}%{ endif }"`,
		`false ? var.o.missing : var.mixed`,
		`true ? (false ? var.mixed : ["y"]) : (true ? ["x"] : var.mixed)`,
		`[for i in [0, 1] : i == 0 ? var.mixed : ["x"]]`,
		`[for i in [0, 1] : i == 0 ? var.o.missing : ["x"]]`,
		`var.c ? var.mixed : ["x"]`,
		`true ? var.o : { b = 1 }`,
	} {
		plain, diags := hclsyntax.ParseExpression([]byte(expr), "x.tf", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", expr, diags)
		}
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": vars}, Functions: plainFunctions()}
		want, wantDiags := plain.Value(ctx)

		rewritten, _ := hclsyntax.ParseExpression([]byte(expr), "x.tf", hcl.InitialPos)
		rewriteForExprs(rewritten)
		m := &ParsedModule{}
		rctx := &hcl.EvalContext{Variables: ctx.Variables, Functions: plainFunctions()}
		for n, f := range m.forFunctionsAnd() {
			rctx.Functions[n] = f
		}
		got, gotDiags := rewritten.Value(rctx)
		if !got.RawEquals(want) || wantDiags.HasErrors() != gotDiags.HasErrors() || len(wantDiags) != len(gotDiags) {
			t.Errorf("%s: iace %#v %v; hcl %#v %v", expr, got, gotDiags, want, wantDiags)
		}
	}
}

// Conditionals in variable defaults (no function table) and with sensitive values evaluate as
// before.
func TestConditionalsEvaluateAsBefore(t *testing.T) {
	t.Parallel()
	secret := Variable{Name: "s", Value: cty.StringVal("FAKE").Mark(SensitiveMark)}
	_, v := evalLocal(t, `false ? "x" : var.s`, map[string]Variable{"s": secret})
	if !v.HasMark(SensitiveMark) {
		t.Errorf("value %#v lost the sensitive mark", v)
	}
	m := parseFilesModule(t, map[string]string{"main.tf": "variable \"v\" {\n  default = true ? \"a\" : \"b\"\n}\n"})
	vars, err := m.EvaluateVariables(context.Background(), m.root, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := vars["v"].Value; !got.RawEquals(cty.StringVal("a")) {
		t.Errorf("default = %#v, diagnostics %v; want \"a\"", got, m.Diagnostics)
	}
	if !strings.HasPrefix(condFalseName, "__iace") {
		t.Fatal("internal name changed")
	}
}

// plainFunctions are the functions the conditional cases call, as hcl would call them.
func plainFunctions() map[string]function.Function {
	return map[string]function.Function{"length": supportedFunctions["length"], "try": tryfunc.TryFunc}
}

// The type decides the cost, so a large tuple nested in an object or a tuple, or an unknown value
// of a large tuple type, is charged too: each took 2.5 to 5 s at 20,000 elements uncharged
// (T-0114c review).
func TestConditionalsChargeTheType(t *testing.T) {
	t.Parallel()
	tup := tupleOf(40_000, cty.StringVal("a"), cty.NumberIntVal(1))
	vars := map[string]Variable{
		"t": {Name: "t", Value: tup},
		"u": {Name: "u", Value: cty.UnknownVal(tup.Type())},
	}
	for _, expr := range []string{
		`true ? { a = var.t } : { a = ["x"] }`,
		`true ? [var.t] : [["x"]]`,
		`true ? var.u : ["x"]`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, _ := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Conditional too large" }) {
				t.Errorf("no limit warning: %v", m.Diagnostics)
			}
		})
	}
}

// A refused conditional makes the whole expression unknown, keeping the sensitivity of every
// value in it.
func TestRefusedConditionalStaysSensitive(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"s": {Name: "s", Value: cty.StringVal("FAKE").Mark(SensitiveMark)},
		"t": {Name: "t", Value: tupleOf(40_000, cty.StringVal("a"))},
	}
	m, v := evalLocal(t, `{ a = var.s, b = true ? var.t : ["x"] }`, vars)
	if v.IsKnown() || !v.HasMark(SensitiveMark) {
		t.Errorf("value known %v, sensitive %v; want unknown and sensitive: %v", v.IsKnown(), v.HasMark(SensitiveMark), m.Diagnostics)
	}
}

// A conditional is charged only when hcl unifies its results' types: not when a result is null
// or dynamic, or both have the same type. `var.enabled ? local.cidrs : null` over 3,000 elements
// cost about 560k units per evaluation, so about 15 instances spent a module's function work
// (T-0114c review). Different types are charged their unification (ADR 0030).
func TestConditionalsChargedOnlyWhenHCLUnifies(t *testing.T) {
	t.Parallel()
	cidrs := tupleOf(3_000, cty.StringVal("10.0.0.0/24"), cty.StringVal("10.0.1.0/24"))
	vars := map[string]Variable{
		"t": {Name: "t", Value: cidrs},
		"c": {Name: "c", Value: cty.UnknownVal(cty.Bool)},
		"d": {Name: "d", Value: cty.DynamicVal},
	}
	for expr, charged := range map[string]bool{
		`var.c ? var.t : null`:                 false,
		`true ? var.t : null`:                  false,
		`false ? null : var.t`:                 false,
		`var.c ? var.t : var.t`:                false,
		`true ? var.t : var.d`:                 false,
		`var.d ? var.t : var.t`:                false,
		`true ? var.t : ["x"]`:                 true,
		`var.c ? ["x"] : var.t`:                true,
		`true ? { a = var.t } : { a = ["x"] }`: true,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			m, _ := evalLocal(t, expr, vars)
			// cty walks each wrapper's argument (ADR 0027): about 144k units per result here.
			// Unifying 3,001 types adds pairs(3,001) ≈ 560k, and converting the values about as
			// much again.
			switch {
			case charged && m.fnWork < 1_000_000:
				t.Errorf("charged %d, want the unification charged", m.fnWork)
			case !charged && m.fnWork > 320_000:
				// Equal types are also charged walking them as cty unifies them (T-0114f):
				// about 12k units here, with no sort.
				t.Errorf("charged %d, want only the walks", m.fnWork)
			}
		})
	}
}

// With both results in hand, nested tuples of different lengths, each within 1,024 elements,
// are charged their unification together: `true ? var.n : [["x"]]` over 36 of them took 8.5 s
// with only per-result charges (T-0114d review).
func TestConditionalsOverNestedTuples(t *testing.T) {
	t.Parallel()
	inner := make([]cty.Value, 36)
	for i := range inner {
		inner[i] = tupleOf(1024-i, cty.StringVal("a"))
	}
	vars := map[string]Variable{"n": {Name: "n", Value: cty.TupleVal(inner)}}
	for _, expr := range []string{
		`true ? var.n : [["x"]]`,
		`false ? var.n : [["x"]]`,
		`false ? [["x"]] : var.n`,
		`true ? __iace_cond_true(__iace_cond_begin(1), var.n) : __iace_cond_false(1, [["x"]])`,
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
			if strings.Contains(expr, "__iace") {
				// Hand-written calls fail on their state argument, which only the rewrite can
				// create, so they reach no conditional's state and nothing is unified.
				if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
					return strings.Contains(d.Detail+d.Summary, "argument")
				}) {
					t.Errorf("no argument error: %v", m.Diagnostics)
				}
				return
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Conditional too large" }) {
				t.Errorf("no limit warning: %v", m.Diagnostics)
			}
		})
	}
}

// Unifying two map types only unifies their element types, but converting a map of lists
// unifies all its entries: `true ? var.m : { a = ["x"] }` over 20,000 entries took 2.7 s while
// the types cost nothing (T-0114e review). Results of different types are charged their
// conversion.
func TestConditionalsChargeConversions(t *testing.T) {
	t.Parallel()
	entries := make(map[string]cty.Value, 20_000)
	for i := range 20_000 {
		entries[fmt.Sprint("k", i)] = cty.ListVal([]cty.Value{cty.NumberIntVal(1)})
	}
	vars := map[string]Variable{"m": {Name: "m", Value: cty.MapVal(entries)}}
	for _, expr := range []string{`true ? var.m : { a = ["x"] }`, `false ? { a = ["x"] } : var.m`} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() || !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Summary == "Conditional too large" }) {
				t.Errorf("value known %v, diagnostics %v; want unknown with a limit warning", v.IsKnown(), m.Diagnostics)
			}
		})
	}
}

// The true result's record is reset before the result is evaluated, so a false result never
// sees one left by an earlier evaluation whose true result failed.
func TestConditionalRecordIsReset(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	fns := m.forFunctions()
	state := newCondState()
	big := tupleOf(3_000, cty.StringVal("a"))
	call := func(name string, args ...cty.Value) cty.Value {
		t.Helper()
		v, err := fns[name].Call(args)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	call(condTrueName, call(condBeginName, state), big)
	call(condFalseName, state, tupleOf(1, cty.StringVal("x")))
	if m.fnWork == 0 {
		t.Fatal("a unifying pair was not charged")
	}
	charged := m.fnWork
	call(condTrueName, call(condBeginName, state), big) // a true result recorded...
	call(condBeginName, state)                          // ...then one that failed before the call
	call(condFalseName, state, tupleOf(1, cty.StringVal("x")))
	if m.fnWork != charged {
		t.Errorf("charged %d for a pair without a true result", m.fnWork-charged)
	}
}
