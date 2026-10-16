package terraform

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Numbers made strings by expressions (T-0124b): hcl converts a template's interpolated parts,
// a for expression's keys, an object constructor's keys and an index into a map to strings
// itself, outside iace's function table, and writing a number as text costs about the square of
// its precision and fractional bits (numberTextCost, ADR 0043): an object for expression over
// 90 multiples of 1e-2466 took 198 ms, charged 8,377 units. Each such part is rewritten once,
// after parsing, to pass through
//
//	__iace_text(S, part)
//
// which returns the value unchanged after charging numberTextCost. S is a capsule no
// configuration can write, so a hand-written call fails. Over the limit the part is a dynamic
// unknown with its marks, and m.textLimited makes evalExpr report it and return the whole value
// unknown. Template parts are wrapped only beside literal text: hcl returns "${x}" as x itself.
const textName = "__iace_text"

// wrapText wraps the parts of n that hcl makes strings (see textName), once.
func wrapText(n hclsyntax.Node) {
	switch n := n.(type) {
	case *hclsyntax.TemplateExpr:
		for i, part := range n.Parts {
			if _, literal := part.(*hclsyntax.LiteralValueExpr); !literal {
				n.Parts[i] = textCall(part)
			}
		}
	case *hclsyntax.ForExpr:
		if n.KeyExpr != nil {
			n.KeyExpr = textCall(n.KeyExpr)
		}
	case *hclsyntax.ObjectConsKeyExpr:
		// A bare name is the key itself, not a reference (hcl.ExprAsKeyword).
		if _, bare := n.Wrapped.(*hclsyntax.ScopeTraversalExpr); bare && !n.ForceNonLiteral && hcl.ExprAsKeyword(n.Wrapped) != "" {
			return
		}
		n.Wrapped = textCall(n.Wrapped)
	case *hclsyntax.IndexExpr:
		n.Key = textCall(n.Key)
	}
}

// textCall returns e wrapped in textName, or e itself when it is a literal or wrapped already.
// A literal is written at the same cost on every evaluation, so it is priced from the source
// instead (literalTextCost): wrapping it would hide literal strings and numbers from code that
// reads them statically (quoted keys in required_providers, optional() defaults with numeric
// keys such as `{ 80 = "http" }`).
func textCall(e hclsyntax.Expression) hclsyntax.Expression {
	switch e := e.(type) {
	case *hclsyntax.LiteralValueExpr:
		return e
	case *hclsyntax.TemplateExpr:
		if e.IsStringLiteral() {
			return e
		}
	case *hclsyntax.FunctionCallExpr:
		if e.Name == textName && len(e.Args) == 2 {
			if lit, ok := e.Args[0].(*hclsyntax.LiteralValueExpr); ok && lit.Val.Type().Equals(condStateType) {
				return e
			}
		}
	}
	r := e.Range()
	return &hclsyntax.FunctionCallExpr{
		Name:      textName,
		Args:      []hclsyntax.Expression{&hclsyntax.LiteralValueExpr{Val: newCondState(), SrcRange: r}, e},
		NameRange: r, OpenParenRange: r, CloseParenRange: r,
	}
}

// textFunction is textName for m: the part, unchanged, after charging the work of writing it as
// text. The part arrives in a capsule, so cty walks nothing of it before the call.
func (m *ParsedModule) textFunction(stateParam function.Parameter) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{stateParam, condResultParam},
		Type:   function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			r := condResult(args[1])
			cost := numberTextCost(r)
			if cost == 0 || m.chargeFunctionWork(cost) {
				return r, nil
			}
			m.spendFunctionWork(cost)
			m.textLimited = true
			_, marks := r.Unmark()
			return cty.DynamicVal.WithMarks(marks), nil
		},
	})
}

// literalTextCost is the work of writing the literal numbers in expr that hcl makes strings,
// each time expr is evaluated: literal template parts, object and for expression keys, index
// keys, and the index steps of traversals (hcl parses local.m[1e-2466] as a traversal, which
// wrapText cannot wrap). total is their numberTextCost summed, and costliest the largest. A
// 512-bit integer costs 121 units, and 1e10000 about 11,000.
//
// An expression whose costliest literal passes maxSetNumberFormatCost (1,089 units, a fraction
// with 1,024 fractional bits) is not safe to evaluate (inspectSource): repeating
// local.m[1e-2466] took 2.2 ms per use. Below that, evalExpr charges total on every evaluation,
// and a for expression charges its body's total on every iteration. Index keys into lists and
// tuples are charged too, though hcl makes them numbers, not text: an accepted over-count (122
// units per `x[0]`).
func literalTextCost(expr hclsyntax.Node) (total, costliest int) {
	add := func(v cty.Value) {
		c := numberTextCost(v)
		total, costliest = min(total+c, maxFunctionWork+1), max(costliest, c)
	}
	literal := func(e hclsyntax.Expression) {
		if lit, ok := e.(*hclsyntax.LiteralValueExpr); ok {
			add(lit.Val)
		}
	}
	traversal := func(t hcl.Traversal) {
		for _, step := range t {
			if ix, ok := step.(hcl.TraverseIndex); ok {
				add(ix.Key)
			}
		}
	}
	_ = hclsyntax.VisitAll(expr, func(n hclsyntax.Node) hcl.Diagnostics {
		switch n := n.(type) {
		case *hclsyntax.ScopeTraversalExpr:
			traversal(n.Traversal)
		case *hclsyntax.RelativeTraversalExpr:
			traversal(n.Traversal)
		case *hclsyntax.TemplateExpr:
			if len(n.Parts) > 1 { // hcl returns "${x}" as x
				for _, part := range n.Parts {
					literal(part)
				}
			}
		case *hclsyntax.ForExpr:
			if n.KeyExpr != nil {
				literal(n.KeyExpr)
			}
		case *hclsyntax.ObjectConsKeyExpr:
			literal(n.Wrapped)
		case *hclsyntax.IndexExpr:
			literal(n.Key)
		}
		return nil
	})
	return total, costliest
}
