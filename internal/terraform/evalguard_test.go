package terraform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// parseOne parses a single file named name and returns the module and the expression of the
// first block's "default" attribute.
func parseOne(t *testing.T, name, src string) (*ParsedModule, hcl.Expression) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{name}}, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	if len(m.Blocks) == 0 {
		t.Fatalf("no blocks parsed; diagnostics: %v", m.Diagnostics)
	}
	attrs, diags := m.Blocks[0].Body.JustAttributes()
	if diags.HasErrors() {
		t.Fatalf("JustAttributes: %v", diags)
	}
	return m, attrs["default"].Expr
}

func hclVar(expr string) string { return "variable \"v\" {\n  default = " + expr + "\n}\n" }

func jsonVar(value string) string { return `{"variable": {"v": {"default": ` + value + `}}}` }

// ctx is a non-nil evaluation context: hcl parses templates in JSON strings only when one is given.
var testCtx = &hcl.EvalContext{Variables: map[string]cty.Value{
	"var": cty.ObjectVal(map[string]cty.Value{"x": cty.StringVal("ok")}),
}}

func TestEvalExprRejectsWhatWouldCrash(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		file, src string
	}{
		// At about 600,000 operators or 300,000 levels each of these kills the process with a
		// fatal stack overflow when evaluated (measured with hcl v2.25.0). The guard trips at
		// maxOperators+1 and maxNesting+1, so ten times the limit proves it is never reached.
		"hcl operator chain":           {"x.tf", hclVar(strings.Repeat("1 + ", 10*maxOperators) + "1")},
		"hcl comparison chain":         {"x.tf", hclVar(strings.Repeat("1 == ", 10*maxOperators) + "1")},
		"json template operator chain": {"x.tf.json", jsonVar(`"${` + strings.Repeat("1+", 10*maxOperators) + `1}"`)},
		"json template nesting":        {"x.tf.json", jsonVar(`"${` + strings.Repeat("(", 10*maxNesting) + "1" + strings.Repeat(")", 10*maxNesting) + `}"`)},
		"json template in a key":       {"x.tf.json", jsonVar(`{"${` + strings.Repeat("1+", 10*maxOperators) + `1}": 1}`)},
		"json template directive":      {"x.tf.json", jsonVar(`"%{ if ` + strings.Repeat("1+", 10*maxOperators) + `1 }y%{ endif }"`)},
		"json nested string":           {"x.tf.json", jsonVar(`[{"a": ["${` + strings.Repeat("!", 10*maxOperators) + `true}"]}]`)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, expr := parseOne(t, tc.file, tc.src)
			v, _ := m.evalExpr(expr, testCtx)
			if v.IsKnown() {
				t.Errorf("evalExpr = %#v, want unknown", v)
			}
			var found bool
			for _, d := range m.Diagnostics {
				if d.Code == DiagExpressionTooComplex {
					found = true
					if d.Severity != SeverityWarning || d.File != tc.file || d.Line < 1 {
						t.Errorf("diagnostic %+v, want a warning naming %s and a line", d, tc.file)
					}
				}
			}
			if !found {
				t.Errorf("no %s diagnostic in %v", DiagExpressionTooComplex, m.Diagnostics)
			}
		})
	}
}

func TestEvalExprEvaluatesSafeExpressions(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		file, src string
		want      cty.Value
	}{
		"hcl at the operator limit":  {"x.tf", hclVar(strings.Repeat("1 + ", maxOperators) + "1"), cty.NumberIntVal(maxOperators + 1)},
		"hcl string":                 {"x.tf", hclVar(`"a-${var.x}"`), cty.StringVal("a-ok")},
		"hcl many interpolations":    {"x.tf", hclVar(`"` + strings.Repeat("${var.x}", 2000) + `"`), cty.StringVal(strings.Repeat("ok", 2000))},
		"json template":              {"x.tf.json", jsonVar(`"a-${var.x}"`), cty.StringVal("a-ok")},
		"json at the operator limit": {"x.tf.json", jsonVar(`"${` + strings.Repeat("1+", maxOperators) + `1}"`), cty.NumberIntVal(maxOperators + 1)},
		"json escaped template":      {"x.tf.json", jsonVar(`"$${not.a.template}"`), cty.StringVal("${not.a.template}")},
		"json plain object":          {"x.tf.json", jsonVar(`{"k": [1, "two"]}`), cty.ObjectVal(map[string]cty.Value{"k": cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.StringVal("two")})})},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, expr := parseOne(t, tc.file, tc.src)
			got, diags := m.evalExpr(expr, testCtx)
			if diags.HasErrors() {
				t.Fatalf("evalExpr diagnostics: %v", diags)
			}
			if !got.RawEquals(tc.want) {
				t.Errorf("evalExpr = %#v, want %#v", got, tc.want)
			}
			if len(m.Diagnostics) != 0 {
				t.Errorf("module diagnostics = %v, want none", m.Diagnostics)
			}
		})
	}
}

func TestEvalExprOneOverTheOperatorLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ file, src string }{
		{"x.tf", hclVar(strings.Repeat("1 + ", maxOperators+1) + "1")},
		{"x.tf.json", jsonVar(`"${` + strings.Repeat("1+", maxOperators+1) + `1}"`)},
	} {
		m, expr := parseOne(t, tc.file, tc.src)
		if v, _ := m.evalExpr(expr, testCtx); v.IsKnown() {
			t.Errorf("%s: evalExpr = %#v, want unknown one past the limit", tc.file, v)
		}
	}
}

func TestEvalExprJSONTemplateNestingLimit(t *testing.T) {
	t.Parallel()
	// "${" opens one level, so maxNesting-1 parentheses reach the limit exactly.
	at := jsonVar(`"${` + strings.Repeat("(", maxNesting-1) + "1" + strings.Repeat(")", maxNesting-1) + `}"`)
	m, expr := parseOne(t, "x.tf.json", at)
	if v, _ := m.evalExpr(expr, testCtx); !v.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("at the nesting limit: evalExpr = %#v, want 1", v)
	}
	over := jsonVar(`"${` + strings.Repeat("(", maxNesting) + "1" + strings.Repeat(")", maxNesting) + `}"`)
	m, expr = parseOne(t, "x.tf.json", over)
	if v, _ := m.evalExpr(expr, testCtx); v.IsKnown() {
		t.Errorf("one over the nesting limit: evalExpr = %#v, want unknown", v)
	}
}

// TestEvalExprFailsClosedWithoutSource: an expression whose file is not one of the module's
// (a --var value, a tfvars file parsed elsewhere) cannot be checked, so it is not evaluated.
func TestEvalExprFailsClosedWithoutSource(t *testing.T) {
	t.Parallel()
	m, _ := parseOne(t, "x.tf", hclVar("1"))
	foreign, diags := hclsyntax.ParseExpression([]byte("1 + 1"), "other.tfvars", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	tests := map[string]hcl.Expression{
		"file not in the module": foreign,
		"static expression":      hcl.StaticExpr(cty.StringVal("x"), hcl.Range{Filename: "x.tf", Start: hcl.Pos{Byte: 5}, End: hcl.Pos{Byte: 1 << 30}}),
	}
	for name, expr := range tests {
		v, _ := m.evalExpr(expr, testCtx)
		if v.IsKnown() {
			t.Errorf("%s: evalExpr = %#v, want unknown", name, v)
		}
	}
	var warnings int
	for _, d := range m.Diagnostics {
		if d.Code == DiagExpressionTooComplex {
			warnings++
		}
	}
	if warnings != 2 {
		t.Errorf("got %d %s diagnostics, want 2: %v", warnings, DiagExpressionTooComplex, m.Diagnostics)
	}

	// Evaluating the same rejected expression again adds no duplicate.
	_, _ = m.evalExpr(foreign, testCtx)
	if len(m.Diagnostics) != warnings {
		t.Errorf("re-evaluation added a duplicate diagnostic: %v", m.Diagnostics)
	}
}

func TestCheckJSONTemplatesRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	if err := checkJSONTemplates("x.tf.json", []byte(`{"a": `)); err == nil {
		t.Error("checkJSONTemplates(truncated JSON) = nil, want an error")
	}
	if err := checkJSONTemplates("x.tf.json", []byte(`{"a": "${var.x}"}`)); err != nil {
		t.Errorf("checkJSONTemplates(valid JSON) = %v, want nil", err)
	}
	if err := checkJSONTemplates("x.tf.json", []byte(`"${`+strings.Repeat("1+", maxOperators+1)+`1}"`)); !errors.Is(err, errTooDeep) {
		t.Errorf("checkJSONTemplates(operator chain) = %v, want errTooDeep", err)
	}
}
