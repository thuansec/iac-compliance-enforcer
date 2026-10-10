package terraform

import (
	"context"
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
// The result is charged that cost first; over the limit it is unknown with a warning, and hcl
// does not unify it (T-0114c).
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
		"same, taken":      {`true ? var.c.same : ["x"]`, false},
		"same, not taken":  {`false ? var.c.same : ["x"]`, true},
		"mixed, taken":     {`true ? var.c.mixed : ["x"]`, false},
		"mixed, not taken": {`false ? var.c.mixed : ["x"]`, true},
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

// The charge is length × length/unifyWorkDivisor plus the types walked, from just past largeTuple.
func TestConditionalBranchCharge(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		n      int
		charge int
	}{
		"at the threshold":   {largeTuple, 0},
		"past the threshold": {largeTuple + 1, (largeTuple+1)*((largeTuple+1)/unifyWorkDivisor) + largeTuple + 2},
	} {
		m := &ParsedModule{}
		if _, err := m.condBranchFunction().Call([]cty.Value{tupleOf(tc.n, cty.True)}); err != nil {
			t.Fatal(err)
		}
		if m.fnWork != tc.charge {
			t.Errorf("%s: charged %d, want %d", name, m.fnWork, tc.charge)
		}
	}
}

// Conditionals evaluate exactly as hcl evaluates them, values, types and diagnostics: only the
// taken result's errors count, none when the condition is unknown, and try sees them; a tuple
// result is not converted. (A first version reported every result's errors and converted tuples
// to lists, which turned Terraform's guard idioms unknown; T-0114c review.)
func TestConditionalsMatchHCL(t *testing.T) {
	t.Parallel()
	mixed := tupleOf(largeTuple+100, cty.StringVal("a"), cty.NumberIntVal(22))
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
	if !strings.HasPrefix(condBranchName, "__iace") {
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

// unifyCost counts nested tuples, and nothing for small types.
func TestUnifyCost(t *testing.T) {
	t.Parallel()
	big := tupleOf(largeTuple+1, cty.True).Type()
	one := (largeTuple + 1) * ((largeTuple + 1) / unifyWorkDivisor)
	walked := largeTuple + 2 // the tuple and its elements
	for name, tc := range map[string]struct {
		ty   cty.Type
		want int
	}{
		"small":       {tupleOf(largeTuple, cty.True).Type(), 0},
		"large":       {big, one + walked},
		"in object":   {cty.Object(map[string]cty.Type{"a": big}), one + walked + 1},
		"in list":     {cty.List(big), one + walked + 1},
		"string list": {cty.List(cty.String), 0},
	} {
		if got := unifyCost(tc.ty, maxFunctionWork); got != tc.want {
			t.Errorf("%s: cost %d, want %d", name, got, tc.want)
		}
	}
	// A type that takes more steps to walk than the limit costs more than the limit, so the
	// walk is never the unbounded part (T-0114c review).
	if got := unifyCost(tupleOf(500, cty.True).Type(), 100); got <= 100 {
		t.Errorf("a 500-step walk with limit 100 costs %d, want more than 100", got)
	}
}
