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
			"The expression is nested too deeply or has too many operators to evaluate safely, so its value is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
		m.sortDiagnostics()
		return cty.DynamicVal, nil
	}
	return expr.Value(ctx)
}

// safeToEvaluate applies the nesting limits and the operator cap to the source of expr. An
// expression whose source cannot be found is not safe.
func (m *ParsedModule) safeToEvaluate(expr hcl.Expression) bool {
	r := expr.Range()
	src, ok := m.src[r.Filename]
	if !ok || r.Start.Byte < 0 || r.Start.Byte > r.End.Byte || r.End.Byte > len(src) {
		return false
	}
	text := src[r.Start.Byte:r.End.Byte]
	if strings.HasSuffix(r.Filename, ".json") {
		return checkJSONTemplates(r.Filename, text) == nil
	}
	tokens, _ := hclsyntax.LexExpression(text, r.Filename, r.Start)
	return scanTokens(tokens, maxOperators) == nil
}

// checkJSONTemplates checks every string in a JSON value, keys included, that hcl would parse as
// a template. It streams tokens, so it does not recurse.
func checkJSONTemplates(name string, text []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(text),
		jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("check JSON expression: %w", err)
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
			return err
		}
	}
}
