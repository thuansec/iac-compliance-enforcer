package terraform

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// forLimited reports whether m has a "For expression too large" diagnostic.
func forLimitedIn(m *ParsedModule) bool {
	return slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
		return d.Code == DiagExpressionTooComplex && d.Summary == "For expression too large"
	})
}

// A for expression's iterations cost forIterationWork plus its body's source bytes each, charged to the
// module's function work: just below, at and just above what is left.
func TestForFunctionChargesIterations(t *testing.T) {
	t.Parallel()
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, 10))
	size, _ := valueSize(list, maxFunctionWork, maxNesting)
	cost := size + 10*(forIterationWork+9) // the collection, and ten iterations of a 9-byte body
	for name, tc := range map[string]struct {
		left    int
		limited bool
	}{
		"below": {cost + 1, false},
		"at":    {cost, false},
		"above": {cost - 1, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := &ParsedModule{fnWork: maxFunctionWork - tc.left}
			got, err := m.forFunction().Call([]cty.Value{closure(list.Mark(SensitiveMark)), cty.NumberIntVal(9), cty.Zero, cty.Zero, cty.Zero})
			if err != nil {
				t.Fatal(err)
			}
			if m.forLimited != tc.limited || got.IsKnown() == tc.limited {
				t.Errorf("limited %v, known %v; want limited %v", m.forLimited, got.IsKnown(), tc.limited)
			}
			if !got.HasMark(SensitiveMark) {
				t.Error("the collection's marks were lost")
			}
			if !tc.limited && m.fnWork != maxFunctionWork-tc.left+cost {
				t.Errorf("charged %d, want %d", m.fnWork-(maxFunctionWork-tc.left), cost)
			}
		})
	}
}

// A configuration may call the function itself: a negative or huge body size cannot refund or
// overflow the work.
func TestForFunctionClampsItsBodySize(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	list := cty.TupleVal([]cty.Value{cty.True})
	if _, err := m.forFunction().Call([]cty.Value{closure(list), cty.NumberIntVal(-1 << 40), cty.Zero, cty.Zero, cty.Zero}); err != nil || m.fnWork != 1+1+forIterationWork {
		t.Errorf("negative body: work %d, err %v; want %d", m.fnWork, err, 1+1+forIterationWork)
	}
	if _, err := m.forFunction().Call([]cty.Value{closure(list), cty.NumberIntVal(1 << 40), cty.Zero, cty.Zero, cty.Zero}); err != nil || !m.forLimited {
		t.Errorf("huge body: limited %v, err %v; want the limit", m.forLimited, err)
	}
}

// Nested for expressions cannot multiply into a hang: three over 1,000 elements (about 1e9
// iterations, which would not finish) stop at the module's work limit with a limit diagnostic.
func TestNestedForExpressionsAreBounded(t *testing.T) {
	t.Parallel()
	m := parseLocalsModule(t, "locals {\n  xs = range(1000)\n  v  = [for a in local.xs : [for b in local.xs : [for c in local.xs : c]]]\n}\n")
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if v := locals["v"].Value; v.IsWhollyKnown() || !forLimitedIn(m) {
		t.Errorf("known %v, diagnostics %v; want unknown with a for-expression limit", v.IsWhollyKnown(), m.Diagnostics)
	}
}

// Ordinary for expressions evaluate as before: in locals, in a variable default (evaluated
// without a context), and over a sensitive collection.
func TestSmallForExpressionsEvaluate(t *testing.T) {
	t.Parallel()
	m, v := evalLocal(t, `{for k, x in {a = 1, b = 2} : upper(k) => x * 2 if x > 1}`, map[string]Variable{})
	if want := cty.ObjectVal(map[string]cty.Value{"B": cty.NumberIntVal(4)}); !v.RawEquals(want) || forLimitedIn(m) {
		t.Errorf("value %#v, want %#v", v, want)
	}
	vm := parseFilesModule(t, map[string]string{"main.tf": "variable \"v\" {\n  default = [for x in [1, 2] : x + 1]\n}\n"})
	vars, err := vm.EvaluateVariables(context.Background(), vm.root, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if want := cty.TupleVal([]cty.Value{cty.NumberIntVal(2), cty.NumberIntVal(3)}); !vars["v"].Value.RawEquals(want) {
		t.Errorf("default %#v, want %#v", vars["v"].Value, want)
	}
	secret := Variable{Name: "s", Value: cty.ListVal([]cty.Value{cty.StringVal("a")}).Mark(SensitiveMark)}
	_, v = evalLocal(t, "[for x in var.s : x]", map[string]Variable{"s": secret})
	if !v.HasMark(SensitiveMark) && !slices.ContainsFunc(v.AsValueSlice(), func(e cty.Value) bool { return e.HasMark(SensitiveMark) }) {
		t.Errorf("value %#v lost the sensitive mark", v)
	}
}

// templatefile templates nest %{ for } directives the same way, and are bounded the same way.
func TestTemplateForDirectivesAreBounded(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": "locals {\n  xs = range(1000)\n  v  = templatefile(\"t.tftpl\", { xs = local.xs })\n}\n",
		"t.tftpl": "%{ for a in xs }%{ for b in xs }%{ for c in xs }${c}%{ endfor }%{ endfor }%{ endfor }",
	})
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if locals["v"].Value.IsKnown() || !forLimitedIn(m) {
		t.Errorf("known %v, diagnostics %v; want unknown with a for-expression limit", locals["v"].Value.IsKnown(), m.Diagnostics)
	}
}

// The instances of a resource charge every evaluation of its for expressions: a for over 100
// elements in a block with count = 10,000 reaches the module's limit, and the later instances
// are unknown.
func TestForExpressionsChargeEveryInstance(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{"main.tf": `
locals {
  xs = range(100)
}
resource "aws_s3_bucket" "b" {
  count = 10000
  tags  = { for i in local.xs : "k${i}" => "${i}${count.index}" }
}
`})
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.DecodeResources(context.Background(), map[string]Variable{}, locals)
	if err != nil {
		t.Fatal(err)
	}
	unknown := 0
	for _, r := range res {
		if len(r.Unknown) > 0 {
			unknown++
		}
	}
	if unknown == 0 || !forLimitedIn(m) {
		t.Errorf("%d of %d instances unknown, diagnostics %v; want the limit reached", unknown, len(res), m.Diagnostics[:min(5, len(m.Diagnostics))])
	}
}

// In .tf.json, a value that is one template string is charged like HCL; a for expression in a
// template nested in an object or array, which hcl evaluates as a whole, is refused.
func TestJSONForExpressions(t *testing.T) {
	t.Parallel()
	nested := `${[for a in local.xs : [for b in local.xs : [for c in local.xs : c]]]}`
	m := parseFilesModule(t, map[string]string{"main.tf.json": `{"locals": {
  "xs": "${range(1000)}",
  "small": "${[for x in [1, 2] : x * 2]}",
  "big": "` + nested + `",
  "inside": {"k": "${[for x in [1] : x]}"}
}}`})
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if want := cty.TupleVal([]cty.Value{cty.NumberIntVal(2), cty.NumberIntVal(4)}); !locals["small"].Value.RawEquals(want) {
		t.Errorf("small = %#v, want %#v", locals["small"].Value, want)
	}
	if locals["big"].Value.IsWhollyKnown() || !forLimitedIn(m) {
		t.Errorf("big is known, or no for-expression limit: %v", m.Diagnostics)
	}
	if locals["inside"].Value.IsKnown() {
		t.Errorf("inside = %#v, want unknown: its for expression cannot be bounded", locals["inside"].Value)
	}
	if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
		return d.Code == DiagExpressionTooComplex && strings.Contains(d.Summary, "too complex")
	}) {
		t.Errorf("no expression_too_complex for the nested template: %v", m.Diagnostics)
	}
}

// A type constraint with a for expression (an optional() default, which typeexpr evaluates
// itself) is refused before typeexpr reads it, in HCL and JSON: its iterations could not be
// charged. The type is unknown with a warning, not an error.
func TestTypeConstraintsWithForExpressionsAreRefused(t *testing.T) {
	t.Parallel()
	big := "[" + strings.TrimSuffix(strings.Repeat("1,", 200), ",") + "]"
	for name, file := range map[string]map[string]string{
		"hcl small": {"main.tf": "variable \"v\" {\n  type = object({ x = optional(list(number), [for a in [1, 2] : a]) })\n}\n"},
		"hcl big":   {"main.tf": "variable \"v\" {\n  type = object({ x = optional(any, [for a in " + big + " : [for b in " + big + " : [for c in " + big + " : c]]]) })\n}\n"},
		"json big":  {"main.tf.json": `{"variable": {"v": {"type": "object({x = optional(any, [for a in ` + big + ` : [for b in ` + big + ` : [for c in ` + big + ` : c]]])})"}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := parseFilesModule(t, file)
			vars, err := m.EvaluateVariables(context.Background(), m.root, VarOptions{}, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if got := vars["v"].Type; got != "any" {
				t.Errorf("type %q, want unknown (any)", got)
			}
			if m.HasErrors() || !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagExpressionTooComplex }) {
				t.Errorf("diagnostics %v, want one expression_too_complex warning", m.Diagnostics)
			}
		})
	}
}

// A body that builds a large value on every iteration is charged that value's size before the
// loop runs, so memory stays within the module's work: a 200 KB string per element allocated
// 393 MB, and nested, about 4 GB (T-0113 review). The same holds for %{ for } directives.
// Indexing a large map element by element is charged per element, not the whole map each time.
func TestForExpressionValuesAreCharged(t *testing.T) {
	big := strings.Repeat("x", 200_000)
	for name, tc := range map[string]struct {
		expr    string
		limited bool
	}{
		"for":       {`[for i in range(1000) : "${local.big}${i}"]`, true},
		"nested":    {`[for a in range(1000) : [for b in range(20) : "${local.big}${b}"]]`, true},
		"directive": {`"%{ for i in range(1000) }${local.big}${i}%{ endfor }"`, true},
		"indexed":   {`[for k in keys(local.m) : local.m[k]]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			// evalExpr directly: the size estimates of locals and attributes would refuse these
			// before evaluation, but other callers (dynamic blocks, module inputs) rely on it.
			m, expr := parseOne(t, "x.tf", hclVar(tc.expr))
			elems := map[string]cty.Value{}
			for i := range 1000 {
				elems[fmt.Sprintf("k%d", i)] = cty.StringVal(fmt.Sprintf("%d-0123456789", i))
			}
			ctx := &hcl.EvalContext{
				Variables: map[string]cty.Value{"local": cty.ObjectVal(map[string]cty.Value{
					"big": cty.StringVal(big), "m": cty.ObjectVal(elems),
				})},
				Functions: m.functions(expr, syntaxCalls(expr.(hclsyntax.Expression))),
			}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			v, _ := m.evalExpr(expr, ctx)
			runtime.ReadMemStats(&after)
			if got := after.TotalAlloc - before.TotalAlloc; got > 100<<20 {
				t.Errorf("allocated %d MB, want at most 100", got>>20)
			}
			if limited := !v.IsWhollyKnown() && forLimitedIn(m); limited != tc.limited {
				t.Errorf("limited %v, want %v: %v", limited, tc.limited, m.Diagnostics)
			}
		})
	}
}

// closure wraps v as the expression argument forFunction takes.
func closure(v cty.Value) cty.Value {
	return customdecode.ExpressionClosureVal(&customdecode.ExpressionClosure{
		Expression: &hclsyntax.LiteralValueExpr{Val: v}, EvalContext: &hcl.EvalContext{},
	})
}

// Measuring is never free: an inner loop over a small collection that holds a large value, and
// a body that refers to a large value once the work is spent, each took a minute or more when
// their walks were not charged (T-0113 review). Both stop at the limit.
func TestForExpressionMeasuringIsCharged(t *testing.T) {
	t.Parallel()
	big := cty.ListVal(slices.Repeat([]cty.Value{cty.NumberIntVal(7)}, 50_000))
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, 2000))
	vars := map[string]Variable{
		"x":    {Name: "x", Value: cty.TupleVal([]cty.Value{big})},
		"big":  {Name: "big", Value: big},
		"list": {Name: "list", Value: list},
	}
	for name, expr := range map[string]string{
		"large collection": "[for a in range(2) : [for b in range(1000) : [for c in var.x : 0]]]",
		"large reference":  "[for b in var.list : [for c in [0] : var.big]]",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, v := evalLocal(t, expr, vars)
			// About 1.5 s, and 30 s under -race with the suite in parallel; unbounded, these
			// took 70 s and an hour.
			if elapsed := time.Since(start); elapsed > 120*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if v.IsWhollyKnown() || !forLimitedIn(m) {
				t.Errorf("known %v, diagnostics %v; want the for-expression limit", v.IsWhollyKnown(), m.Diagnostics)
			}
		})
	}
}

// A refused for expression spends only the work it did, so the rest of the module still
// evaluates: a small call after it is known.
func TestRefusedForExpressionLeavesTheRestOfTheWork(t *testing.T) {
	t.Parallel()
	m, expr := parseOne(t, "x.tf", hclVar(`[for a in range(1000) : "${local.big}"]`))
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"local": cty.ObjectVal(map[string]cty.Value{"big": cty.StringVal(strings.Repeat("x", 200_000))})},
		Functions: m.functions(expr, syntaxCalls(expr.(hclsyntax.Expression))),
	}
	if v, _ := m.evalExpr(expr, ctx); v.IsWhollyKnown() || !forLimitedIn(m) {
		t.Fatalf("the large for expression was not limited: %v", m.Diagnostics)
	}
	after, diags := hclsyntax.ParseExpression([]byte(`upper("x")`), "x.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if got, _ := after.Value(ctx); !got.RawEquals(cty.StringVal("X")) {
		t.Errorf("upper(\"x\") = %#v after the refused loop, want \"X\": the loop spent the module's work", got)
	}
}
