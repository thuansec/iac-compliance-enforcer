package terraform

import (
	"encoding/json"
	"errors"
	"math/big"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// For expressions iterate inside hcl, where iace cannot count. Nested for expressions multiply:
// three over a 200-element list build 8 million elements, and over 1,000 elements about a
// billion (T-0104c review). A body can also build a large value on every iteration
// ("${local.big}${i}"), which its source size does not bound (T-0113 review). So every for
// expression in a syntax tree iace evaluates is rewritten once, after parsing, to iterate over
//
//	__iace_for(collection, bodyBytes, iteratorUses, __iace_refs(whole...), __iace_elems(indexed...))
//
// (ADR 0020). The function returns the collection unchanged after charging, before the loop
// runs, what its iterations can build:
//   - each iteration: forIterationWork, the body's source bytes, the size of every value the
//     body refers to outside its own iterators (__iace_refs), and the largest element of every
//     value it only indexes (__iace_elems, for local.m[k]);
//   - once: the collection's size for every use of the iterators, whose values are its
//     elements.
//
// Nested for expressions in the body charge themselves. Over the limit, the function returns an
// unknown collection, so the for expression is unknown and evalExpr reports it. Nested loops,
// and the instances of a resource, charge every evaluation, so the module's function work bounds
// them all together.

// The internal functions rewritten for expressions call.
const (
	forFunctionName  = "__iace_for"
	forRefsName      = "__iace_refs"
	forElementsName  = "__iace_elems"
	forIterationWork = 16 // creating an iteration's scope and its result values
)

// errForInJSONTemplate refuses a for expression in a .tf.json template string nested in an
// object or array: hcl parses those templates only while it evaluates the whole value, so they
// cannot be rewritten to charge their iterations. A value that is a single template string is
// evaluated by iace instead (jsonStringTemplate), so its for expressions are charged.
var errForInJSONTemplate = errors.New("for expression in a JSON template string, which iace cannot bound")

// rewriteForExprs makes every for expression in node iterate over forFunctionName. It is
// idempotent, so a tree parsed once and rewritten twice is unchanged.
func rewriteForExprs(node hclsyntax.Node) {
	_ = hclsyntax.VisitAll(node, func(n hclsyntax.Node) hcl.Diagnostics {
		f, ok := n.(*hclsyntax.ForExpr)
		if !ok {
			return nil
		}
		if c, ok := f.CollExpr.(*hclsyntax.FunctionCallExpr); ok && c.Name == forFunctionName {
			return nil // rewritten already
		}
		body, uses := 0, 0
		var whole, indexed []hclsyntax.Expression
		for _, e := range []hclsyntax.Expression{f.KeyExpr, f.ValExpr, f.CondExpr} {
			if e == nil {
				continue
			}
			r := e.Range()
			body += max(r.End.Byte-r.Start.Byte, 0)
			w, i, u := bodyReferences(e, f.KeyVar, f.ValVar)
			whole, indexed, uses = append(whole, w...), append(indexed, i...), uses+u
		}
		r := f.CollExpr.Range()
		call := func(name string, args ...hclsyntax.Expression) *hclsyntax.FunctionCallExpr {
			return &hclsyntax.FunctionCallExpr{Name: name, Args: args, NameRange: r, OpenParenRange: r, CloseParenRange: r}
		}
		number := func(n int) hclsyntax.Expression {
			return &hclsyntax.LiteralValueExpr{Val: cty.NumberIntVal(int64(n)), SrcRange: r}
		}
		f.CollExpr = call(forFunctionName, f.CollExpr, number(body), number(uses),
			call(forRefsName, whole...), call(forElementsName, indexed...))
		return nil
	})
}

// bodyReferences lists the references of a for expression's body e, outside the nested for
// expressions, which charge themselves: whole are the values it may copy whole, indexed those it
// only indexes (local.m[k]), and uses counts the uses of the iterators key and value.
func bodyReferences(e hclsyntax.Expression, key, value string) (whole, indexed []hclsyntax.Expression, uses int) {
	var nested []hcl.Range
	elements := map[*hclsyntax.ScopeTraversalExpr]bool{}
	_ = hclsyntax.VisitAll(e, func(n hclsyntax.Node) hcl.Diagnostics {
		switch n := n.(type) {
		case *hclsyntax.ForExpr:
			nested = append(nested, n.Range())
		case *hclsyntax.IndexExpr:
			if t, ok := n.Collection.(*hclsyntax.ScopeTraversalExpr); ok {
				elements[t] = true
			}
		case *hclsyntax.RelativeTraversalExpr:
			if t, ok := n.Source.(*hclsyntax.ScopeTraversalExpr); ok && len(n.Traversal) > 0 {
				if _, index := n.Traversal[0].(hcl.TraverseIndex); index {
					elements[t] = true
				}
			}
		}
		return nil
	})
	inside := func(r hcl.Range) bool {
		return slices.ContainsFunc(nested, func(f hcl.Range) bool {
			return r.Filename == f.Filename && f.Start.Byte <= r.Start.Byte && r.End.Byte <= f.End.Byte
		})
	}
	_ = hclsyntax.VisitAll(e, func(n hclsyntax.Node) hcl.Diagnostics {
		t, ok := n.(*hclsyntax.ScopeTraversalExpr)
		if !ok || inside(t.Range()) {
			return nil
		}
		switch root := t.Traversal.RootName(); {
		case root == key || root == value:
			uses++
		case elements[t]:
			indexed = append(indexed, t)
		default:
			whole = append(whole, t)
		}
		return nil
	})
	return whole, indexed, uses
}

// hasForExpr reports whether node holds a for expression.
func hasForExpr(node hclsyntax.Node) bool {
	found := false
	_ = hclsyntax.VisitAll(node, func(n hclsyntax.Node) hcl.Diagnostics {
		if _, ok := n.(*hclsyntax.ForExpr); ok {
			found = true
		}
		return nil
	})
	return found
}

// forFunction is forFunctionName for m: the collection, unchanged, if the module can pay for
// what its iterations can build; an unknown value otherwise, with m.forLimited set. It takes the
// collection as an expression and evaluates it itself, so cty never walks the value for free,
// and it measures the value only up to the work left, charging what it measures: an inner loop
// over a small collection that holds a large value pays for that value on every evaluation.
func (m *ParsedModule) forFunction() function.Function {
	if m.forFn != nil {
		return *m.forFn
	}
	f := function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "collection", Type: customdecode.ExpressionClosureType},
			{Name: "body", Type: cty.Number},
			{Name: "uses", Type: cty.Number},
			{Name: "refs", Type: cty.Number},
			{Name: "elems", Type: cty.Number},
		},
		Type: function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			coll, diags := customdecode.ExpressionClosureFromVal(args[0]).Value()
			m.forDiags = append(m.forDiags, diags...) // hcl would have reported them itself
			if diags.HasErrors() || !coll.IsKnown() || coll.IsNull() {
				return coll, nil
			}
			unmarked, marks := coll.Unmark() // the top level only: a deep walk would be free work
			limited := func() (cty.Value, error) {
				m.forLimited = true
				return cty.DynamicVal.WithMarks(marks), nil
			}
			left := maxFunctionWork - m.fnWork
			if left <= 0 {
				return limited()
			}
			ty := unmarked.Type()
			if !ty.IsCollectionType() && !ty.IsTupleType() && !ty.IsObjectType() {
				return coll, nil // hcl reports that it cannot iterate over it
			}
			size, ok := valueSize(coll, left, maxNesting)
			if !ok {
				m.spendFunctionWork(left) // measured all that was left
				return limited()
			}
			perIteration := forIterationWork + clampWork(args[1]) + clampWork(args[3]) + clampWork(args[4])
			if !m.chargeFunctionWork(size, saturatingMul(unmarked.LengthInt(), perIteration),
				saturatingMul(clampWork(args[2]), size)) {
				m.spendFunctionWork(size) // the walk done; the loop itself never runs
				return limited()
			}
			return coll, nil
		},
	})
	m.forFn = &f
	return f
}

// forReferencesFunction is forRefsName (whole) or forElementsName: the total size of the
// values its argument expressions refer to, or of their largest elements. A reference that
// cannot be evaluated counts nothing: the body may never evaluate it (an empty collection), and
// hcl reports it if it does. Each value is measured only up to the work left, and the
// measurement is charged; with no work left, nothing is walked and the result is the whole limit,
// so the loop that asked is refused.
func (m *ParsedModule) forReferencesFunction(elements bool) function.Function {
	return function.New(&function.Spec{
		VarParam: &function.Parameter{Name: "refs", Type: customdecode.ExpressionClosureType},
		Type:     function.StaticReturnType(cty.Number),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			exhausted := cty.NumberIntVal(maxFunctionWork)
			total := 0
			for _, a := range args {
				left := maxFunctionWork - m.fnWork
				if left <= 0 {
					return exhausted, nil
				}
				v, diags := customdecode.ExpressionClosureFromVal(a).Value()
				if diags.HasErrors() {
					continue
				}
				n, ok := valueSize(v, left, maxNesting)
				if !ok {
					m.spendFunctionWork(left) // measured all that was left
					return exhausted, nil
				}
				m.spendFunctionWork(n)
				if elements {
					n = largestElement(v)
				}
				total = min(total+n, maxFunctionWork)
			}
			return cty.NumberIntVal(int64(total)), nil
		},
	})
}

// largestElement is the size of v's largest element, or of v if it has none.
func largestElement(v cty.Value) int {
	v, _ = v.Unmark()
	ty := v.Type()
	if !v.IsKnown() || v.IsNull() || !ty.IsCollectionType() && !ty.IsTupleType() && !ty.IsObjectType() {
		n, _ := valueSize(v, maxFunctionWork, maxNesting)
		return n
	}
	largest := 0
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		n, _ := valueSize(e, maxFunctionWork, maxNesting)
		largest = max(largest, n)
	}
	return largest
}

// clampWork reads a work argument, clamped to [0, maxFunctionWork]: a configuration may call the
// internal functions itself with any number.
func clampWork(v cty.Value) int {
	if !v.IsKnown() || v.IsNull() || v.IsMarked() {
		return maxFunctionWork
	}
	n := v.AsBigFloat()
	switch {
	case n.Sign() < 0:
		return 0
	case n.Cmp(big.NewFloat(maxFunctionWork)) > 0:
		return maxFunctionWork
	}
	i, _ := n.Int64()
	return int(i)
}

// forFunctions are the internal functions rewritten for expressions call.
func (m *ParsedModule) forFunctions() map[string]function.Function {
	return map[string]function.Function{
		forFunctionName: m.forFunction(),
		forRefsName:     m.forReferencesFunction(false),
		forElementsName: m.forReferencesFunction(true),
	}
}

// withForFunction returns ctx with the internal functions in scope, as a child so the caller's
// context is not changed; nil becomes a context with only those functions.
func (m *ParsedModule) withForFunction(ctx *hcl.EvalContext) *hcl.EvalContext {
	fns := m.forFunctions()
	if ctx == nil {
		return &hcl.EvalContext{Functions: fns}
	}
	child := ctx.NewChild()
	child.Functions = fns
	return child
}

// jsonStringTemplate returns, for a .tf.json expression that is a single string, the template
// hcl would parse from it at evaluation, with its for expressions rewritten, so they are charged
// as in HCL; ok is false for any other expression. It parses the string as hcl's JSON decoder
// does: from the byte after the opening quote.
func (m *ParsedModule) jsonStringTemplate(expr hcl.Expression) (hclsyntax.Expression, bool) {
	r := expr.Range()
	src, ok := m.src[r.Filename]
	if !ok || r.Start.Byte < 0 || r.Start.Byte >= r.End.Byte || r.End.Byte > len(src) || src[r.Start.Byte] != '"' {
		return nil, false
	}
	var s string
	if err := json.Unmarshal(src[r.Start.Byte:r.End.Byte], &s); err != nil {
		return nil, false
	}
	tmpl, diags := hclsyntax.ParseTemplate([]byte(s), r.Filename,
		hcl.Pos{Line: r.Start.Line, Column: r.Start.Column + 1, Byte: r.Start.Byte + 1})
	if diags.HasErrors() {
		return nil, false // hcl reports the same errors when it evaluates expr
	}
	rewriteForExprs(tmpl)
	return tmpl, true
}

// callsForFunctions reports whether expr, inspected already, holds a rewritten for expression.
func (m *ParsedModule) callsForFunctions(expr hcl.Expression) bool {
	calls, _ := m.inspectExpr(expr)
	return slices.ContainsFunc(calls, func(c functionCall) bool { return c.name == forFunctionName })
}
