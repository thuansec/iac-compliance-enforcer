package terraform

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// lookupCall evaluates src, a lookup call rewritten as iace rewrites every tree it evaluates,
// with local.m and local.big in scope, on a module with the given work left.
func lookupCall(t *testing.T, src string, left int) (*ParsedModule, cty.Value) {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "x.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	rewriteForExprs(expr)
	if c, ok := expr.(*hclsyntax.FunctionCallExpr); !ok || c.Name != lookupFunctionName {
		t.Fatalf("%s was not rewritten to %s", src, lookupFunctionName)
	}
	m := &ParsedModule{fnWork: maxFunctionWork - left}
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"local": cty.ObjectVal(map[string]cty.Value{
			"m": cty.MapVal(map[string]cty.Value{
				"a": cty.StringVal("x"),
				"s": cty.StringVal("y").Mark(SensitiveMark),
			}).Mark("outer"),
			"big":    cty.StringVal(strings.Repeat("z", 1000)),
			"secret": cty.StringVal("a").Mark(SensitiveMark),
			"sdflt":  cty.StringVal("d").Mark(SensitiveMark),
		})},
		Functions: m.forFunctionsAnd(),
	}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	return m, v
}

// lookup charges only what it returns, 1 plus its size, however large the map: just below, at
// and just above the work left.
func TestLookupChargesItsResult(t *testing.T) {
	t.Parallel()
	cost := 1 + 2 // "x": one value and one byte
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
			m, v := lookupCall(t, `lookup(local.m, "a", "d")`, tc.left)
			if m.fnLimited != tc.limited || v.IsKnown() == tc.limited {
				t.Errorf("limited %v, value %#v; want limited %v", m.fnLimited, v, tc.limited)
			}
			if !tc.limited && (!v.HasMark("outer") || m.fnWork != maxFunctionWork-tc.left+cost) {
				t.Errorf("value %#v, charged %d; want the map's mark and %d", v, m.fnWork-(maxFunctionWork-tc.left), cost)
			}
		})
	}
}

// lookup keeps the map's marks and the element's own, uses the default only for a missing key,
// and charges a large default like any result.
func TestLookupMarksAndDefaults(t *testing.T) {
	t.Parallel()
	if _, v := lookupCall(t, `lookup(local.m, "s", "d")`, maxFunctionWork); !v.HasMark(SensitiveMark) || !v.HasMark("outer") {
		t.Errorf("lookup of a sensitive element = %#v, want it sensitive and with the map's mark", v)
	}
	if _, v := lookupCall(t, `lookup(local.m, "missing", "d")`, maxFunctionWork); !v.RawEquals(cty.StringVal("d").Mark("outer")) {
		t.Errorf("lookup of a missing key = %#v, want the default with the map's mark", v)
	}
	if _, v := lookupCall(t, `lookup(local.m, local.secret, "d")`, maxFunctionWork); !v.HasMark(SensitiveMark) {
		t.Errorf("lookup with a sensitive key = %#v, want it sensitive", v)
	}
	if _, v := lookupCall(t, `lookup(local.m, "missing", local.sdflt)`, maxFunctionWork); !v.HasMark(SensitiveMark) {
		t.Errorf("lookup falling back to a sensitive default = %#v, want it sensitive", v)
	}
	if m, v := lookupCall(t, `lookup(local.m, "missing", local.big)`, 100); v.IsKnown() || !m.fnLimited {
		t.Errorf("a 1,000-byte default with 100 work left = known %v, limited %v; want it limited", v.IsKnown(), m.fnLimited)
	}
}

// Templates rewrite lookup too: templatefile evaluates its template's tree, which is rewritten.
func TestTemplateLookupsAreRewritten(t *testing.T) {
	t.Parallel()
	tmpl, diags := hclsyntax.ParseTemplate([]byte(`${lookup(m, "a", "d")}`), "t.tftpl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	rewriteForExprs(tmpl)
	found := false
	_ = hclsyntax.VisitAll(tmpl, func(n hclsyntax.Node) hcl.Diagnostics {
		if c, ok := n.(*hclsyntax.FunctionCallExpr); ok && c.Name == lookupFunctionName {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("the template's lookup was not rewritten")
	}
}

// Calls of any arity in a for body are rewritten safely: a call with no arguments once panicked
// while its references were read (T-0113e review), which crashed the scan on untrusted input.
func TestRewriteHandlesCallsOfAnyArity(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		`{ for k in ["a"] : k => timestamp() }`,
		`[for k in ["a"] : uuid()]`,
		`[for k in ["a"] : upper(k)]`,
		`[for k in ["a"] : lookup(k)]`,
		`[for k in ["a"] : lookup({}, k, 1, 2)]`,
		`[for k in ["a"] : lookup([{a = 1}]...)]`,
	} {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "x.tf", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", src, diags)
		}
		rewriteForExprs(expr)
	}
}

// An error never quotes the key, which may be sensitive.
func TestLookupErrorsDoNotQuoteTheKey(t *testing.T) {
	t.Parallel()
	key := cty.StringVal("FAKE-secret-key").Mark(SensitiveMark)
	for name, args := range map[string][]cty.Value{
		"object without the attribute": {cty.EmptyObjectVal, key},
		"map without the key":          {cty.MapValEmpty(cty.String), key},
	} {
		if _, _, err := lookupValue(args); err == nil || strings.Contains(err.Error(), "FAKE-secret-key") {
			t.Errorf("%s: error %v; want an error that does not quote the key", name, err)
		}
	}
}
