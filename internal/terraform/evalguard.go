package terraform

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// maxOperators caps the binary operators in one expression. Evaluation recurses once per
// operand, so an unbounded chain ("1+1+...+1") exhausts the stack and kills the process; real
// expressions use a handful.
const maxOperators = 1000

// evalExpr is the only way this package evaluates an expression. It first checks the
// expression's own source: the file-level nesting guard does not bound operator chains, and
// templates inside .tf.json strings are parsed only now, at evaluation. An expression that fails
// the check, or whose source is not one of the module's files, is not evaluated: it is unknown,
// and a warning diagnostic records where (once per location). Anything else that makes hcl parse
// JSON templates, such as Variables() on a .tf.json expression, must pass safeToEvaluate first.
func (m *ParsedModule) evalExpr(expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	if !m.safeToEvaluate(expr) {
		r := expr.Range()
		m.diag(SeverityWarning, DiagExpressionTooComplex, "Expression too complex",
			"The expression is nested too deeply, or has too many operators or chained steps, to evaluate safely, so its value is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
		m.sortDiagnostics()
		return cty.DynamicVal, nil
	}
	m.fnLimited, m.fnDiags = false, nil
	val, diags := expr.Value(ctx)
	r := expr.Range()
	if m.fnLimited {
		m.diag(SeverityWarning, DiagFunctionLimit, "Function call too large",
			"A function call would pass the size or work limit for function calls, so its value is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
	}
	for _, d := range m.fnDiags {
		m.diag(SeverityWarning, d.code, d.summary, d.detail, r.Filename, r.Start.Line, r.Start.Column)
	}
	m.fnDiags = nil
	m.sortDiagnostics()
	return val, diags
}

// safeToEvaluate applies the nesting limits and the operator cap to the source of expr. An
// expression whose source cannot be found is not safe.
func (m *ParsedModule) safeToEvaluate(expr hcl.Expression) bool {
	_, ok := m.inspectExpr(expr)
	return ok
}

// inspectExpr reports whether expr is safe to evaluate, as safeToEvaluate, and if so lists the
// functions it calls.
func (m *ParsedModule) inspectExpr(expr hcl.Expression) ([]functionCall, bool) {
	r := expr.Range()
	src, ok := m.src[r.Filename]
	if !ok || r.Start.Byte < 0 || r.Start.Byte > r.End.Byte || r.End.Byte > len(src) {
		return nil, false
	}
	text := src[r.Start.Byte:r.End.Byte]
	if isJSON(expr) {
		calls, err := jsonTemplateCalls(r.Filename, text)
		return calls, err == nil
	}
	tokens, _ := hclsyntax.LexExpression(text, r.Filename, r.Start)
	if scanTokens(tokens, maxOperators) != nil {
		return nil, false
	}
	if se, ok := expr.(hclsyntax.Expression); ok {
		return syntaxCalls(se), true
	}
	return nil, true
}

// checkJSONTemplates checks every string in a JSON value, keys included, that hcl would parse as
// a template.
func checkJSONTemplates(name string, text []byte) error {
	_, err := jsonTemplateCalls(name, text)
	return err
}

// jsonTemplateCalls checks the templates in a JSON value like checkJSONTemplates and lists the
// functions they call. It streams tokens, so it does not recurse.
func jsonTemplateCalls(name string, text []byte) ([]functionCall, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(text),
		jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	var calls []functionCall
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return calls, nil
		}
		if err != nil {
			return nil, fmt.Errorf("check JSON expression: %w", err)
		}
		if tok.Kind() != '"' {
			continue
		}
		s := tok.String()
		if !strings.Contains(s, "${") && !strings.Contains(s, "%{") {
			continue
		}
		tokens, _ := hclsyntax.LexTemplate([]byte(s), name, hcl.InitialPos)
		if err := scanTokens(tokens, maxOperators); err != nil {
			return nil, err
		}
		if tmpl, diags := hclsyntax.ParseTemplate([]byte(s), name, hcl.InitialPos); !diags.HasErrors() {
			calls = append(calls, syntaxCalls(tmpl)...)
		}
	}
}
