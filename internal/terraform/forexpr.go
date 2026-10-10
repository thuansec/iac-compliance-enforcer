package terraform

import (
	"encoding/json"
	"math/big"
	"reflect"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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
	forResultName    = "__iace_val"
	forIterationWork = 64 // creating an iteration's scope and its result values: about 1.3 KB allocated (T-0113a)
)

// rewriteForExprs makes every for expression in node iterate over forFunctionName, and every
// lookup call call lookupFunctionName (ADR 0023). It is idempotent, so a tree parsed once and
// rewritten twice is unchanged.
func rewriteForExprs(node hclsyntax.Node) {
	directives := map[*hclsyntax.ForExpr]bool{}
	_ = hclsyntax.VisitAll(node, func(n hclsyntax.Node) hcl.Diagnostics {
		renameLookup(n) // ADR 0023
		wrapBranches(n) // ADR 0028
		if j, ok := n.(*hclsyntax.TemplateJoinExpr); ok {
			if f, ok := j.Tuple.(*hclsyntax.ForExpr); ok {
				directives[f] = true // visited before its for expression
			}
			return nil
		}
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
		if directives[f] {
			// A %{ for } directive joins the strings its iterations produce, and a directive
			// nested in its body hands it strings that grow with each level, which the
			// iterations do not bound: each string is charged as it is produced.
			vr := f.ValExpr.Range()
			f.ValExpr = &hclsyntax.FunctionCallExpr{
				Name: forResultName, Args: []hclsyntax.Expression{f.ValExpr},
				NameRange: vr, OpenParenRange: vr, CloseParenRange: vr,
			}
		}
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
		case *hclsyntax.FunctionCallExpr:
			// lookup reads one element of its map (ADR 0023).
			if isLookupCall(n) { // it has two or three arguments
				if t, ok := n.Args[0].(*hclsyntax.ScopeTraversalExpr); ok {
					elements[t] = true
				}
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

// forResultFunction is forResultName for m: an iteration's result, unchanged, if the module can
// pay for its size, measured only up to the work left; an unknown value otherwise, with
// m.forLimited set. Directive results are strings, whose size is their length.
func (m *ParsedModule) forResultFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "result", Type: cty.DynamicPseudoType, AllowUnknown: true, AllowNull: true, AllowMarked: true, AllowDynamicType: true},
		},
		Type: func(args []cty.Value) (cty.Type, error) { return args[0].Type(), nil },
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			left := maxFunctionWork - m.fnWork
			n, ok := valueSize(args[0], max(left, 0), maxNesting)
			if ok && m.chargeFunctionWork(n) {
				return args[0], nil
			}
			m.spendFunctionWork(n)
			m.forLimited = true
			_, marks := args[0].Unmark()
			return cty.UnknownVal(retType).WithMarks(marks), nil
		},
	})
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
	fns := map[string]function.Function{
		forFunctionName: m.forFunction(),
		forRefsName:     m.forReferencesFunction(false),
		forElementsName: m.forReferencesFunction(true),
		forResultName:   m.forResultFunction(),
	}
	for name, f := range m.condFunctions() {
		fns[name] = f
	}
	return fns
}

// withForFunction returns ctx with the internal functions in scope (for expressions and lookup),
// as a child so the caller's context is not changed; nil becomes a context with only those
// functions.
func (m *ParsedModule) withForFunction(ctx *hcl.EvalContext) *hcl.EvalContext {
	fns := m.forFunctionsAnd()
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

// callsForFunctions reports whether expr, inspected already, holds a rewritten for expression or
// conditional, which need the internal functions in scope even without a function table.
func (m *ParsedModule) callsForFunctions(expr hcl.Expression) bool {
	calls, _ := m.inspectExpr(expr)
	return slices.ContainsFunc(calls, func(c functionCall) bool {
		return c.name == forFunctionName || c.name == condFalseName
	})
}

// evalJSON evaluates a .tf.json value as hcl's JSON decoder does, member by member, but parses
// every template string itself (jsonStringTemplate), so the for expressions in templates nested
// in objects and arrays are rewritten and charged like any other (T-0113b). Object keys are
// templates too, as in hcl. ctx is never nil here: without a context, hcl keeps strings literal.
func (m *ParsedModule) evalJSON(expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	pairs, elems, container := jsonContainer(expr)
	switch {
	case !container:
		if tmpl, ok := m.jsonStringTemplate(expr); ok {
			return tmpl.Value(ctx)
		}
		return expr.Value(ctx) // numbers, booleans, null, or a template hcl reports as invalid
	case elems != nil:
		vals := make([]cty.Value, 0, len(elems))
		var diags hcl.Diagnostics
		for _, e := range elems {
			v, d := m.evalJSON(e, ctx)
			vals, diags = append(vals, v), append(diags, d...)
		}
		return cty.TupleVal(vals), diags
	}
	var diags hcl.Diagnostics
	attrs := map[string]cty.Value{}
	known := true
	for _, p := range pairs {
		name, nameDiags := m.evalJSON(p.Key, ctx)
		val, valDiags := m.evalJSON(p.Value, ctx)
		diags = append(diags, nameDiags...)
		diags = append(diags, valDiags...)
		invalid := func(detail string) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError, Summary: "Invalid object key expression", Detail: detail,
				Subject: p.Key.Range().Ptr(),
			})
		}
		name, err := convert.Convert(name, cty.String)
		switch {
		case err != nil:
			invalid("Cannot use this expression as an object key.")
			continue
		case name.IsNull():
			invalid("Cannot use null value as an object key.")
			continue
		case !name.IsKnown():
			known = false // the object's type cannot be known, as in hcl
			continue
		case name.IsMarked():
			invalid("Cannot use a sensitive value as an object key.") // hcl would panic
			continue
		}
		key := name.AsString()
		if _, defined := attrs[key]; defined {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError, Summary: "Duplicate object attribute",
				Detail: "An attribute of this name was already defined.", Subject: p.Key.Range().Ptr(),
			})
			continue
		}
		attrs[key] = val
	}
	if !known {
		return cty.DynamicVal, diags
	}
	return cty.ObjectVal(attrs), diags
}

// Conditionals (ADR 0030): hcl evaluates both results of a conditional, then, unless one is a
// dynamic null or of the dynamic type, unifies their types and converts the taken result to the
// unified type. Unifying sorts element types comparing every pair (ADR 0029), so a conditional
// over a large tuple took seconds. Each conditional's results are wrapped so the work is
// charged with both results in hand, just before hcl unifies:
//
//	c ? a : b  →  c ? __iace_cond_true(__iace_cond_begin(S), a) : __iace_cond_false(S, b)
//
// hcl evaluates the true result first, and a call's arguments in order: begin resets the
// conditional's state S, the true wrapper records a's value in it, and the false wrapper
// charges unifying it with b's, as hcl is about to. The wrappers take the results as ordinary
// arguments, so hcl evaluates them with its own rules for diagnostics, marks and unknowns, and
// return them unchanged. S is a capsule only the rewrite can create: a configuration that calls
// the functions itself cannot reach or forge another conditional's state.
const (
	condBeginName = "__iace_cond_begin"
	condTrueName  = "__iace_cond_true"
	condFalseName = "__iace_cond_false"
)

// condState is one conditional's record of its true result during an evaluation.
type condState struct {
	trueResult cty.Value
	recorded   bool
}

// condStateType is the capsule type of a conditional's state.
var condStateType = cty.Capsule("iace conditional", reflect.TypeOf(condState{}))

// newCondState returns a fresh conditional state as a capsule value.
func newCondState() cty.Value {
	return cty.CapsuleVal(condStateType, &condState{})
}

// wrapBranches wraps the results of a conditional (see condBeginName), once: the rewrite's own
// wrappers are recognised by their state capsule, which no configuration can write.
func wrapBranches(n hclsyntax.Node) {
	c, ok := n.(*hclsyntax.ConditionalExpr)
	if !ok {
		return
	}
	if call, ok := c.FalseResult.(*hclsyntax.FunctionCallExpr); ok && call.Name == condFalseName && len(call.Args) == 2 {
		if lit, ok := call.Args[0].(*hclsyntax.LiteralValueExpr); ok && lit.Val.Type().Equals(condStateType) {
			return
		}
	}
	state := newCondState()
	call := func(name string, args ...hclsyntax.Expression) hclsyntax.Expression {
		r := args[len(args)-1].Range()
		return &hclsyntax.FunctionCallExpr{
			Name: name, Args: args, NameRange: r, OpenParenRange: r, CloseParenRange: r,
		}
	}
	literal := func(r hcl.Range) hclsyntax.Expression {
		return &hclsyntax.LiteralValueExpr{Val: state, SrcRange: r}
	}
	tr, fr := c.TrueResult.Range(), c.FalseResult.Range()
	c.TrueResult = call(condTrueName, call(condBeginName, literal(tr)), c.TrueResult)
	c.FalseResult = call(condFalseName, literal(fr), c.FalseResult)
}

// condStateOf returns the state a capsule argument holds.
func condStateOf(v cty.Value) *condState {
	s, _ := v.EncapsulatedValue().(*condState)
	return s
}

// condResultParam is the parameter a wrapper takes a result in: any value, as hcl gives it.
var condResultParam = function.Parameter{
	Name: "result", Type: cty.DynamicPseudoType,
	AllowUnknown: true, AllowNull: true, AllowMarked: true, AllowDynamicType: true,
}

// condFunctions are the conditional wrappers for m.
func (m *ParsedModule) condFunctions() map[string]function.Function {
	stateParam := function.Parameter{Name: "state", Type: condStateType}
	return map[string]function.Function{
		condBeginName: function.New(&function.Spec{
			Params: []function.Parameter{stateParam},
			Type:   function.StaticReturnType(condStateType),
			Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
				*condStateOf(args[0]) = condState{}
				return args[0], nil
			},
		}),
		condTrueName: function.New(&function.Spec{
			Params: []function.Parameter{stateParam, condResultParam},
			Type:   function.StaticReturnType(cty.DynamicPseudoType),
			Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
				*condStateOf(args[0]) = condState{trueResult: args[1], recorded: true}
				return args[1], nil
			},
		}),
		condFalseName: m.condFalseFunction(stateParam),
	}
}

// condFalseFunction is condFalseName for m: the false result, unchanged, after charging the
// unification hcl is about to do with the recorded true result, if it will: not when either
// result is a dynamic null or of the dynamic type. The charge is unifying the two types
// (unifyTypesCost) and, when they differ, converting both values to the unified type (only the
// taken one is converted, so this can over-count). Over the limit the false result is a dynamic
// unknown with its marks, so hcl does not unify, and m.condLimited is set, which makes
// evalExpr return the whole value unknown.
func (m *ParsedModule) condFalseFunction(stateParam function.Parameter) function.Function {
	dynamicNull := cty.NullVal(cty.DynamicPseudoType)
	return function.New(&function.Spec{
		Params: []function.Parameter{stateParam, condResultParam},
		// Dynamic: a refused result must be an unknown without its type, or hcl would still
		// unify that type.
		Type: function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			state, f := condStateOf(args[0]), args[1]
			t, recorded := state.trueResult, state.recorded
			*state = condState{}
			switch {
			case !recorded, t.RawEquals(dynamicNull), f.RawEquals(dynamicNull),
				t.Type() == cty.DynamicPseudoType, f.Type() == cty.DynamicPseudoType:
				return f, nil // hcl does not unify
			}
			limit := maxFunctionWork - m.fnWork
			cost := unifyTypesCost([]cty.Type{t.Type(), f.Type()}, limit)
			if !t.Type().Equals(f.Type()) {
				// Converting a value can cost more than unifying the types: a map of lists
				// converted to another map of lists unifies all its entries (T-0114e review).
				cost = min(cost+valueConversionCost(t, limit)+valueConversionCost(f, limit), maxFunctionWork+1)
			}
			if cost == 0 || m.chargeFunctionWork(cost) {
				return f, nil
			}
			m.spendFunctionWork(cost) // a refusal pays for the walk, so it cannot repeat for free
			m.condLimited = true
			_, marks := f.Unmark()
			return cty.DynamicVal.WithMarks(marks), nil
		},
	})
}
