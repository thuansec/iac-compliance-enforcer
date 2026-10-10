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
	m.fnLimited, m.fnDiags, m.forLimited, m.forDiags, m.condLimited = false, nil, false, nil, false
	var val cty.Value
	var diags hcl.Diagnostics
	switch {
	case ctx == nil && isJSON(expr):
		val, diags = expr.Value(nil) // strings stay literal, as hcl's JSON decoder keeps them
	case isJSON(expr):
		// iace evaluates every JSON value itself (ADR 0024): its template strings are rewritten
		// like HCL's, and a sensitive object key is an error where hcl's decoder panics.
		val, diags = m.evalJSON(expr, m.withForFunction(ctx))
	case m.callsForFunctions(expr):
		val, diags = expr.Value(m.withForFunction(ctx))
	default:
		val, diags = expr.Value(ctx) // contexts without functions keep hcl's own errors
	}
	diags, m.forDiags = append(diags, m.forDiags...), nil
	r := expr.Range()
	if m.condLimited {
		m.diag(SeverityWarning, DiagExpressionTooComplex, "Conditional too large",
			"A result of a conditional holds a tuple so long that unifying its type with the other result's would pass the work limit for function calls, so that result was not unified and may be unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
	}
	if m.forLimited {
		m.diag(SeverityWarning, DiagExpressionTooComplex, "For expression too large",
			"A for expression would iterate past the work limit, so its value is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
	}
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

// inspection is inspectExpr's result for one expression.
type inspection struct {
	calls []functionCall
	safe  bool
}

// setSource records a file's bytes for the expression checks, forgetting any inspection of
// earlier bytes under the same name.
func (m *ParsedModule) setSource(name string, data []byte) {
	if m.src == nil {
		m.src = map[string][]byte{}
	}
	m.src[name] = data
	delete(m.inspected, name)
}

// dropSource forgets a file's bytes and its inspections.
func (m *ParsedModule) dropSource(name string) {
	delete(m.src, name)
	delete(m.inspected, name)
}

// forgetInspections drops the memo when a stage of evaluation ends (variables, locals, module
// inputs, resources): within a stage each expression is lexed once, and the memo, about 11 times
// the source it covers, is not kept for the rest of the scan.
func (m *ParsedModule) forgetInspections() {
	m.inspected = nil
}

// inspectExpr reports whether expr is safe to evaluate, as safeToEvaluate, and if so lists the
// functions it calls. Results are memoized by source range (inspected): evaluating an expression
// checks it again, and so does each instance of a count or for_each resource.
func (m *ParsedModule) inspectExpr(expr hcl.Expression) ([]functionCall, bool) {
	r := expr.Range()
	src, ok := m.src[r.Filename]
	if !ok || r.Start.Byte < 0 || r.Start.Byte > r.End.Byte || r.End.Byte > len(src) {
		return nil, false
	}
	key := [2]int{r.Start.Byte, r.End.Byte}
	if in, ok := m.inspected[r.Filename][key]; ok {
		return in.calls, in.safe
	}
	calls, safe := m.inspectSource(expr, src[r.Start.Byte:r.End.Byte])
	if m.inspected == nil {
		m.inspected = map[string]map[[2]int]inspection{}
	}
	if m.inspected[r.Filename] == nil {
		m.inspected[r.Filename] = map[[2]int]inspection{}
	}
	m.inspected[r.Filename][key] = inspection{calls, safe}
	return calls, safe
}

// inspectSource is inspectExpr without the memo: text is expr's source.
func (m *ParsedModule) inspectSource(expr hcl.Expression, text []byte) ([]functionCall, bool) {
	r := expr.Range()
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
			if hasForExpr(tmpl) {
				// iace evaluates such a value itself (evalJSON), so its for expressions are
				// charged; the marker makes callsForFunctions choose that path.
				calls = append(calls, functionCall{name: forFunctionName})
			}
			calls = append(calls, syntaxCalls(tmpl)...)
		}
	}
}
