package terraform

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Diagnostic codes for function calls.
const (
	// DiagUnsupportedFunction: an expression calls a function iace does not evaluate (a
	// provider-defined, impure or not yet supported one), so the call is unknown. Reported once
	// per function name per module, at the first call.
	DiagUnsupportedFunction DiagCode = "unsupported_function"
	// DiagFunctionLimit: a function call would pass the size or work limit for function calls,
	// so its value is unknown. It is a limit_exceeded coverage gap.
	DiagFunctionLimit DiagCode = "function_limit"
)

// Limits on function calls. Sizes are valueSize units: one per value plus one per string byte,
// map key or attribute name.
const (
	// maxFunctionValueSize bounds the arguments of one call together, and its result. It equals
	// maxLocalValueSize: a larger result could not be a local's value anyway.
	maxFunctionValueSize = maxLocalValueSize
	// maxFunctionWork bounds the work of all of a module's function calls together: the size of
	// every call's arguments and result.
	maxFunctionWork = 1 << 23
	// jsonEscapeFactor bounds how much format's %v (or %q) can grow a value: JSON escapes one
	// byte as at most six ("\u0000").
	jsonEscapeFactor = 6
)

// supportedFunctions maps each Terraform function iace evaluates to its implementation: a go-cty
// stdlib function, or iace's own where Terraform's semantics differ from any stdlib function.
// Only functions whose semantics match Terraform's, and whose cost the
// argument and result sizes bound, are listed; docs/reference/terraform-functions.md documents
// the table, and every other function evaluates as unknown. Keep both in sync. Functions that
// build sets are charged by setBuildCosts.
var supportedFunctions = map[string]function.Function{
	// Terraform's own semantics, implemented in functions_terraform.go and functions_network.go
	"base64decode": base64DecodeFunc,
	"base64encode": base64EncodeFunc,
	"cidrhost":     cidrHostFunc,
	"cidrnetmask":  cidrNetmaskFunc,
	"cidrsubnet":   cidrSubnetFunc,
	"coalesce":     coalesceFunc,
	"endswith":     endsWithFunc,
	"index":        indexFunc,
	"length":       lengthFunc,
	"lookup":       lookupFunc,
	"startswith":   startsWithFunc,
	"strcontains":  strContainsFunc,
	// string
	"chomp":      stdlib.ChompFunc,
	"format":     stdlib.FormatFunc,
	"formatlist": stdlib.FormatListFunc,
	"join":       stdlib.JoinFunc,
	"lower":      stdlib.LowerFunc,
	"split":      stdlib.SplitFunc,
	"substr":     stdlib.SubstrFunc,
	"title":      stdlib.TitleFunc,
	"trim":       stdlib.TrimFunc,
	"trimprefix": stdlib.TrimPrefixFunc,
	"trimspace":  stdlib.TrimSpaceFunc,
	"trimsuffix": stdlib.TrimSuffixFunc,
	"upper":      stdlib.UpperFunc,
	// collection
	"chunklist":       stdlib.ChunklistFunc,
	"coalescelist":    stdlib.CoalesceListFunc,
	"compact":         stdlib.CompactFunc,
	"concat":          stdlib.ConcatFunc,
	"contains":        stdlib.ContainsFunc,
	"distinct":        stdlib.DistinctFunc,
	"element":         stdlib.ElementFunc,
	"flatten":         stdlib.FlattenFunc,
	"keys":            stdlib.KeysFunc,
	"merge":           stdlib.MergeFunc,
	"range":           stdlib.RangeFunc,
	"reverse":         stdlib.ReverseListFunc,
	"setintersection": stdlib.SetIntersectionFunc,
	"setsubtract":     stdlib.SetSubtractFunc,
	"setunion":        stdlib.SetUnionFunc,
	"slice":           stdlib.SliceFunc,
	"sort":            stdlib.SortFunc,
	"values":          stdlib.ValuesFunc,
	"zipmap":          stdlib.ZipmapFunc,
	// type conversion
	"tobool":   stdlib.MakeToFunc(cty.Bool),
	"tolist":   stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tomap":    stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)),
	"tonumber": stdlib.MakeToFunc(cty.Number),
	"toset":    stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
	"tostring": stdlib.MakeToFunc(cty.String),
	// encoding
	"jsondecode": stdlib.JSONDecodeFunc,
	"jsonencode": stdlib.JSONEncodeFunc,
	// numeric
	"abs":    stdlib.AbsoluteFunc,
	"max":    stdlib.MaxFunc,
	"min":    stdlib.MinFunc,
	"signum": stdlib.SignumFunc,
}

// unboundedFunctions take expressions rather than values and do no work of their own; the
// calls inside their arguments are bounded.
var unboundedFunctions = map[string]function.Function{
	"can": tryfunc.CanFunc,
	"try": tryfunc.TryFunc,
}

// callCost returns a bound on the size of a call's result and the work the call does beyond
// measuring its arguments and result, for a function whose result or work can grow faster than
// its arguments. sizes are the arguments' valueSize.
type callCost func(args []cty.Value, sizes []int) (out, work int)

// callCosts lists the functions whose result or work can grow faster than their arguments.
var callCosts = map[string]callCost{
	"contains":   comparisonCost,
	"format":     formatCost,
	"formatlist": formatListCost,
	"index":      comparisonCost,
}

// setBuildCosts lists the functions that build sets or compare every pair of elements, from
// their arguments or while converting them. Their work is charged before the arguments are
// converted, both when the call's type is decided and when it runs.
var setBuildCosts = map[string]callCost{
	"distinct":        setBuildCost,
	"setintersection": setBuildCost,
	"setsubtract":     setBuildCost,
	"setunion":        setBuildCost,
	"toset":           setBuildCost,
}

// unifyingFunctions convert or unify their arguments inside the call, beyond the conversion to
// their parameter types: each argument is charged its conversion to the type given, or, for the
// dynamic type, to a type not known before the call (conservativeCost), with the arguments'
// types unified together (ADR 0029, ADR 0032).
var unifyingFunctions = map[string]cty.Type{
	"coalesce": cty.DynamicPseudoType, // unifies the arguments' types, then converts each to the result
	"lookup":   cty.DynamicPseudoType, // converts the default to a map's element type (only expanded calls reach it: ADR 0023)
	"tolist":   cty.List(cty.DynamicPseudoType),
	"tomap":    cty.Map(cty.DynamicPseudoType),
	"toset":    cty.Set(cty.DynamicPseudoType),
}

// unknownFunction stands in for every function iace does not evaluate. Its parameters do not
// allow marks, so cty marks its unknown result with every mark of its arguments.
var unknownFunction = function.New(&function.Spec{
	Description: "Any function iace does not evaluate: the result is unknown.",
	VarParam: &function.Parameter{
		Name:             "args",
		Type:             cty.DynamicPseudoType,
		AllowNull:        true,
		AllowUnknown:     true,
		AllowDynamicType: true,
	},
	Type: function.StaticReturnType(cty.DynamicPseudoType),
	Impl: func([]cty.Value, cty.Type) (cty.Value, error) { return cty.DynamicVal, nil },
})

// functionCall is a function name an expression calls, at its first call.
type functionCall struct {
	name string
	pos  hcl.Pos
}

// syntaxCalls lists the functions expr calls, in source order, with namespaced names
// ("provider::aws::arn_parse") as hcl records them. expr must have passed the nesting guard,
// which bounds the walk's recursion.
func syntaxCalls(expr hclsyntax.Expression) []functionCall {
	var calls []functionCall
	_ = hclsyntax.VisitAll(expr, func(n hclsyntax.Node) hcl.Diagnostics {
		if c, ok := n.(*hclsyntax.FunctionCallExpr); ok {
			calls = append(calls, functionCall{name: c.Name, pos: c.NameRange.Start})
		}
		return nil
	})
	return calls
}

// functions returns the function table for evaluating expr, whose calls are listed in calls:
// every supported function, bounded, and unknownFunction for any other name expr calls. The
// first call of each unsupported name in the module is reported. A name in Terraform's
// "core::" namespace is the built-in function of that name.
func (m *ParsedModule) functions(expr hcl.Expression, calls []functionCall) map[string]function.Function {
	if m.fns == nil {
		m.fns = make(map[string]function.Function, len(supportedFunctions)+len(unboundedFunctions))
		for name, f := range supportedFunctions {
			m.fns[name] = m.bounded(f, setBuildCosts[name], callCosts[name], unifyingFunctions[name])
		}
		for name, f := range unboundedFunctions {
			m.fns[name] = f
		}
		for name, f := range m.fileFunctions() {
			m.fns[name] = m.bounded(f, nil, nil, cty.NilType)
		}
		for name, f := range m.forFunctions() {
			m.fns[name] = f
		}
		m.fns[lookupFunctionName] = m.lookupFunction()
		m.fns["replace"] = m.bounded(m.replaceFunc(), nil, nil, cty.NilType)
		m.fns["regex"] = m.bounded(m.regexFunc(false), nil, nil, cty.NilType)
		m.fns["regexall"] = m.bounded(m.regexFunc(true), nil, nil, cty.NilType)
		m.unsupportedSeen = map[string]bool{}
	}
	fns := m.fns
	copied := false
	for _, c := range calls {
		if _, ok := fns[c.name]; ok {
			continue
		}
		if !copied {
			fns, copied = make(map[string]function.Function, len(m.fns)+len(calls)), true
			for name, f := range m.fns {
				fns[name] = f
			}
		}
		if f, ok := m.fns[strings.TrimPrefix(c.name, "core::")]; ok {
			fns[c.name] = f
			continue
		}
		fns[c.name] = unknownFunction
		if !m.unsupportedSeen[c.name] {
			m.unsupportedSeen[c.name] = true
			pos := c.pos
			if isJSON(expr) {
				pos = expr.Range().Start // template positions are relative to the JSON string
			}
			m.diag(SeverityWarning, DiagUnsupportedFunction, fmt.Sprintf("Unsupported function %q", c.name),
				"iace does not evaluate this function, so the values that use it are unknown.",
				expr.Range().Filename, pos.Line, pos.Column)
		}
	}
	return fns
}

// bounded wraps f so that a call over the function limits is unknown instead of evaluated, and
// sets m.fnLimited so evalExpr reports it. cost, if not nil, bounds f's result; before, if not
// nil, bounds work that converting the arguments or calling f can do, and is checked before
// they are converted. Converting an argument to a parameter type that holds a collection
// type, or to unify when it is not cty.NilType, is charged its unification (conversionWork).
// The wrapper keeps f's parameters but takes any type: hcl converts arguments to the
// parameter types before a call, and converting a large number to a string,
// for example, costs as much as the number's digits, so the wrapper converts them itself once
// their size is checked. cty then handles unknown, null and marked arguments exactly as for f.
func (m *ParsedModule) bounded(f function.Function, before, cost callCost, unify cty.Type) function.Function {
	params := slices.Clone(f.Params())
	for i := range params {
		params[i].Type = cty.DynamicPseudoType
	}
	var varParam *function.Parameter
	if vp := f.VarParam(); vp != nil {
		p := *vp
		p.Type = cty.DynamicPseudoType
		varParam = &p
	}
	// measure returns the arguments' sizes, their total and the work before converting them.
	// measured is false when the arguments together pass the size limit, and affordable when
	// the module can also pay for that work; a call is converted only then.
	measure := func(args []cty.Value) (sizes []int, total, pre int, measured, affordable bool) {
		sizes, measured = measureArgs(args, m.functionArgsLimit())
		if !measured {
			return sizes, 0, 0, false, false
		}
		for _, n := range sizes {
			total += n
		}
		if before != nil {
			_, pre = before(args, sizes)
		}
		pre = min(pre+m.conversionWork(f, args, unify), maxFunctionWork+1)
		return sizes, total, pre, true, m.canChargeFunctionWork(total, pre)
	}
	return function.New(&function.Spec{
		Description: f.Description(),
		Params:      params,
		VarParam:    varParam,
		Type: func(args []cty.Value) (cty.Type, error) {
			// cty calls Impl only when every argument is known, so the conversion here,
			// which can build sets, is charged here: a call with an unknown argument would
			// otherwise repeat it for free.
			_, total, pre, measured, affordable := measure(args)
			// When Impl will not run (cty skips it, or this pass fails), the walk measure just
			// made is all that is done: it is charged here, once, or such calls would walk
			// their arguments for free (T-0114j). Impl charges it otherwise.
			paid := false
			payWalk := func() {
				if paid {
					return
				}
				paid = true
				m.spendFunctionWork(total)
				if !measured {
					m.spendFunctionWork(m.functionArgsLimit())
				}
			}
			if skipsCall(params, varParam, args) || !affordable && before != nil {
				payWalk()
			}
			if !affordable {
				m.fnLimited = true // Impl may not run: cty skips it when an argument is unknown
				// The conversion estimate walked the arguments' types, which an unknown
				// argument does not bound: a refusal pays for it, so it cannot repeat for free.
				m.spendFunctionWork(pre)
				return cty.DynamicPseudoType, nil
			}
			m.spendFunctionWork(pre)
			conv, err := convertArgs(f, args)
			if err != nil {
				payWalk() // an error stops the call; can and try catch it, so it can repeat
				return cty.DynamicPseudoType, err
			}
			ty, err := f.ReturnTypeForValues(conv)
			if err != nil {
				payWalk()
			}
			return ty, err
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			limited := func() (cty.Value, error) {
				m.fnLimited = true
				unknown := cty.UnknownVal(retType)
				if slices.ContainsFunc(args, cty.Value.ContainsMarked) {
					unknown = unknown.Mark(SensitiveMark) // fail closed
				}
				return unknown, nil
			}
			argsLimit := m.functionArgsLimit()
			sizes, total, pre, measured, affordable := measure(args)
			if !measured {
				// Measuring stopped at argsLimit; a refused call still spends that work, so
				// refused calls cannot repeat for free.
				m.spendFunctionWork(argsLimit)
				return limited()
			}
			if !affordable {
				m.spendFunctionWork(total)
				return limited()
			}
			conv, err := convertArgs(f, args)
			if err != nil {
				return cty.NilVal, err
			}
			out, work := 0, 0
			if cost != nil {
				out, work = cost(conv, sizes)
			}
			if out > maxFunctionValueSize || !m.chargeFunctionWork(total, pre, work) {
				m.spendFunctionWork(total)
				return limited()
			}
			val, err := f.Call(conv)
			if err != nil {
				return cty.NilVal, err
			}
			if errs := val.Type().TestConformance(retType); errs != nil && retType != cty.DynamicPseudoType {
				// f decided its type again and differently (a limit reached in between): an
				// unknown result is a limit, anything else a bug that must not become a value.
				if !val.IsKnown() {
					return limited()
				}
				return cty.NilVal, fmt.Errorf("function result does not conform to its type: %w", errs[0])
			}
			size, ok := valueSize(val, maxFunctionValueSize, maxNesting)
			if !ok || !m.chargeFunctionWork(size) {
				return limited()
			}
			return val, nil
		},
	})
}

// skipsCall reports whether cty will return an unknown result for a call with args without
// calling Impl (function.Function.Call): an argument is unknown and its parameter does not
// allow unknown values. cty decides the other cases in which it does not call Impl (too many
// arguments, a dynamic-typed argument its parameter does not allow) before the type pass runs.
func skipsCall(params []function.Parameter, varParam *function.Parameter, args []cty.Value) bool {
	for i, a := range args {
		spec := varParam
		if i < len(params) {
			spec = &params[i]
		}
		if spec != nil && !a.IsKnown() && !spec.AllowUnknown {
			return true
		}
	}
	return false
}

// functionArgsLimit is the largest total argument size a call may have: maxFunctionValueSize,
// or less once the module's work budget runs low, so that calls stop measuring arguments when
// it is spent.
func (m *ParsedModule) functionArgsLimit() int {
	return min(maxFunctionValueSize, maxFunctionWork-m.fnWork)
}

// measureArgs returns the size of each of args, which together may not pass limit. ok is false
// when they do; measuring stops there.
func measureArgs(args []cty.Value, limit int) (sizes []int, ok bool) {
	sizes = make([]int, len(args))
	total := 0
	for i, a := range args {
		n, ok := valueSize(a, limit-total, maxNesting)
		if !ok {
			return sizes, false
		}
		sizes[i] = n
		total += n
	}
	return sizes, true
}

// conversionWork is the work of the conversions f makes of args (ADR 0029, ADR 0032): an
// argument is charged its conversionCost to its parameter type when that type holds a
// collection type. When unify is not cty.NilType, every argument is charged its conversion to
// unify instead, or, for the dynamic type, conservativeCost and the arguments' types unified
// together (coalesce).
func (m *ParsedModule) conversionWork(f function.Function, args []cty.Value, unify cty.Type) int {
	params, varParam := f.Params(), f.VarParam()
	work := 0
	for i, a := range args {
		left := maxFunctionWork - m.fnWork
		want := cty.DynamicPseudoType
		switch {
		case i < len(params):
			want = params[i].Type
		case varParam != nil:
			want = varParam.Type
		}
		var n int
		switch {
		case unify == cty.DynamicPseudoType:
			n = conservativeCost(a, left)
		case unify != cty.NilType:
			n = conversionCost(a, unify, false, left)
		case typeHasCollection(want):
			n = conversionCost(a, want, false, left)
		}
		work = min(work+n, maxFunctionWork+1)
	}
	if unify == cty.DynamicPseudoType && len(args) > 1 {
		types := make([]cty.Type, len(args))
		for i, a := range args {
			types[i] = a.Type()
		}
		work = min(work+unifyTypesCost(types, maxFunctionWork-m.fnWork), maxFunctionWork+1)
	}
	return work
}

// convertArgs converts each of args to the type of f's parameter, as hcl would before calling
// f. Measure the arguments first: converting can cost more than their size.
func convertArgs(f function.Function, args []cty.Value) ([]cty.Value, error) {
	params, varParam := f.Params(), f.VarParam()
	conv := make([]cty.Value, len(args))
	for i, a := range args {
		var ty cty.Type
		switch {
		case i < len(params):
			ty = params[i].Type
		case varParam != nil:
			ty = varParam.Type
		default:
			return nil, function.NewArgErrorf(i, "too many arguments")
		}
		var err error
		if conv[i], err = convert.Convert(a, ty); err != nil {
			return nil, function.NewArgError(i, err)
		}
	}
	return conv, nil
}

// chargeFunctionWork adds work to the module's function work, unless that would pass
// maxFunctionWork. Each amount is at most maxFunctionWork, so the sum cannot overflow.
func (m *ParsedModule) chargeFunctionWork(amounts ...int) bool {
	if !m.canChargeFunctionWork(amounts...) {
		return false
	}
	m.fnWork += workSum(amounts)
	return true
}

// canChargeFunctionWork reports whether chargeFunctionWork would charge amounts.
func (m *ParsedModule) canChargeFunctionWork(amounts ...int) bool {
	return workSum(amounts) <= maxFunctionWork-m.fnWork
}

// workSum adds amounts, each capped just above maxFunctionWork so the sum cannot overflow.
func workSum(amounts []int) int {
	sum := 0
	for _, n := range amounts {
		sum += min(n, maxFunctionWork+1)
	}
	return sum
}

// spendFunctionWork charges n, or whatever work is left if that is less.
func (m *ParsedModule) spendFunctionWork(n int) {
	m.fnWork += min(max(n, 0), maxFunctionWork-m.fnWork)
}

// formatCost bounds format: each verb can print any argument, padded to its width.
func formatCost(args []cty.Value, sizes []int) (out, work int) {
	if len(args) == 0 || !args[0].IsKnown() || args[0].IsNull() {
		return 0, 0
	}
	largest := 0
	for _, n := range sizes[1:] {
		largest = max(largest, n)
	}
	f, _ := args[0].Unmark()
	return formatBound(f.AsString(), largest), 0
}

// formatListCost bounds formatlist: one format result per row, where the rows are as many as
// the longest list argument and each verb prints at most the largest element.
func formatListCost(args []cty.Value, sizes []int) (out, work int) {
	if len(args) == 0 || !args[0].IsKnown() || args[0].IsNull() {
		return 0, 0
	}
	rows, largest := 1, 0
	for i, a := range args[1:] {
		a, _ = a.Unmark()
		ty := a.Type()
		if !a.IsKnown() || a.IsNull() || !ty.IsListType() && !ty.IsTupleType() {
			largest = max(largest, sizes[i+1])
			continue
		}
		rows = max(rows, a.LengthInt())
		for it := a.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			n, _ := valueSize(ev, maxFunctionValueSize, maxNesting)
			largest = max(largest, n)
		}
	}
	f, _ := args[0].Unmark()
	return saturatingMul(rows, formatBound(f.AsString(), largest)), 0
}

// comparisonCost charges contains and index: they compare the value with each element of the
// list, and cty walks both for marks and unknowns on every comparison, so one comparison costs
// the element's size plus the value's. Equals then recurses and walks each subtree again at
// every level, so that is multiplied by the depth of the recursion plus one, which the value's
// nesting depth bounds (recursion stops at the shallower side). The work is (elements × the
// value's size + the list's size) × (the value's depth + 1) (T-0114h: contains(var.t, var.t)
// over 10,000 elements took 21 s, and 500-deep values 25 s, uncharged). With sets, comparing is
// pairwise (setComparisonWork).
func comparisonCost(args []cty.Value, sizes []int) (out, work int) {
	if len(args) < 2 {
		return 0, 0
	}
	elems := 0
	if list, _ := args[0].Unmark(); list.IsKnown() && !list.IsNull() && list.CanIterateElements() {
		elems = list.LengthInt()
	}
	flat := min(saturatingMul(elems, sizes[1])+sizes[0], maxFunctionWork+1)
	work = saturatingMul(flat, valueDepth(args[1])+1)
	return 0, max(work, setComparisonWork(args, sizes))
}

// valueDepth is v's nesting depth: 0 for a primitive, unknown or null value, one more than its
// deepest element otherwise, capped at maxNesting. v must have been measured, which bounds the
// walk.
func valueDepth(v cty.Value) int {
	type item struct {
		val   cty.Value
		depth int
	}
	deepest := 0
	stack := []item{{val: v}}
	for len(stack) > 0 && deepest < maxNesting {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		val, _ := it.val.Unmark()
		deepest = max(deepest, it.depth)
		if !val.IsKnown() || val.IsNull() || !val.CanIterateElements() {
			continue
		}
		for elems := val.ElementIterator(); elems.Next(); {
			_, e := elems.Element()
			stack = append(stack, item{e, it.depth + 1})
		}
	}
	return min(deepest, maxNesting)
}

// setComparisonWork is the pairwise work of comparing values that hold sets, for
// functions that compare elements of a collection with a value (contains, index). cty compares
// two sets by looking up each element of one in the other, and when number hashes collide
// (cty hashes ten significant digits) each lookup compares every element: the work is bounded
// by the product of the sizes. Values without sets compare in linear time.
func setComparisonWork(args []cty.Value, sizes []int) int {
	if len(args) < 2 || !typeHasSet(args[0].Type()) && !typeHasSet(args[1].Type()) {
		return 0
	}
	return saturatingMul(sizes[0], sizes[1])
}

// setBuildCost charges building a set from the elements of every argument (toset, the set
// functions) or comparing every pair of them (distinct). cty hashes a number by its first ten
// significant digits, so close numbers share a hash, and each element added is compared with
// every element of its hash: the work is bounded by the number of elements times their total
// comparison weight. When the elements can hold sets, comparing two of them compares their
// elements pairwise in turn, so the work is bounded by the total weight squared.
func setBuildCost(args []cty.Value, _ []int) (out, work int) {
	elems, weight, nested, compound, costliest := 0, 0, false, false, 0
	for _, a := range args {
		w, c := comparisonWeight(a)
		weight, costliest = min(weight+w, maxFunctionWork+1), max(costliest, c)
		a, _ = a.Unmark()
		if !a.IsKnown() || a.IsNull() {
			continue
		}
		ty := a.Type()
		switch {
		case ty.IsCollectionType():
			nested = nested || typeHasSet(ty.ElementType())
			compound = compound || !ty.ElementType().IsPrimitiveType()
		case ty.IsTupleType():
			nested = nested || slices.ContainsFunc(ty.TupleElementTypes(), typeHasSet)
			compound = compound || slices.ContainsFunc(ty.TupleElementTypes(), func(et cty.Type) bool { return !et.IsPrimitiveType() })
		default:
			continue // not a collection: converting it fails
		}
		elems += a.LengthInt()
	}
	if compound && costliest > maxSetNumberFormatCost {
		// cty orders a set of compound values by their hashes, so every later iteration of the
		// set hashes its numbers again, at a cost no later size check sees.
		return 0, maxFunctionWork + 1
	}
	if nested {
		return 0, saturatingMul(weight, weight)
	}
	return 0, saturatingMul(elems, weight)
}

// maxSetNumberFormatCost is the largest numberFormatCost of a number inside a set element
// that is not a primitive value. Every number with up to 1,024 fractional bits passes (0.1 has
// about 515 at cty's 512-bit precision).
const maxSetNumberFormatCost = (1024/fracBitsPerUnitRoot + 1) * (1024/fracBitsPerUnitRoot + 1)

// comparisonWeight bounds the work of comparing or hashing v once: its valueSize, plus the
// formatting cost of each number in it. costliest is the largest formatting cost of one
// number. v must have been measured, which bounds the walk.
func comparisonWeight(v cty.Value) (weight, costliest int) {
	stack := []cty.Value{v}
	for len(stack) > 0 && weight <= maxFunctionWork {
		val, _ := stack[len(stack)-1].Unmark()
		stack = stack[:len(stack)-1]
		weight++
		ty := val.Type()
		switch {
		case !val.IsKnown() || val.IsNull():
		case ty == cty.String:
			weight += len(val.AsString())
		case ty == cty.Number:
			c := numberFormatCost(val)
			weight += numberDigits(val) + c
			costliest = max(costliest, c)
		case ty.IsCollectionType() || ty.IsObjectType() || ty.IsTupleType():
			for elems := val.ElementIterator(); elems.Next(); {
				k, ev := elems.Element()
				if k, _ := k.Unmark(); k.Type() == cty.String && k.IsKnown() && !k.IsNull() {
					weight += len(k.AsString())
				}
				stack = append(stack, ev)
			}
		}
	}
	return min(weight, maxFunctionWork+1), costliest
}

// fracBitsPerUnitRoot calibrates numberFormatCost: formatting a number with 2^18 fractional
// bits (1e-78000) took 1.9s, about 10.6M work units, so one format covers at least 80² squared
// bits per unit. A set function formats each number several times per charge (the type pass,
// the conversion, setunion adding every element again, hashing compound elements while
// sorting), so 32² keeps a timing sweep at or under about 120ns per unit.
const fracBitsPerUnitRoot = 32

// numberFormatCost bounds the work of writing a number as decimal text beyond its digits. cty
// compares two numbers that are not integers by their exact decimal text, and hashes them by a
// rounded one, and math/big builds the exact expansion by shifting it 60 bits at a time, which
// is quadratic in the number's fractional bits: one comparison of 1e-78000 takes seconds.
func numberFormatCost(v cty.Value) int {
	f := v.AsBigFloat()
	if f.IsInf() || f.Sign() == 0 {
		return 0
	}
	frac := int(f.MinPrec()) - f.MantExp(nil)
	if frac <= 0 {
		return 0
	}
	q := frac/fracBitsPerUnitRoot + 1
	return saturatingMul(q, q)
}

// typeHasSet reports whether a value of type ty can hold a set.
func typeHasSet(ty cty.Type) bool {
	switch {
	case ty == cty.DynamicPseudoType || ty.IsSetType():
		return true
	case ty.IsListType() || ty.IsMapType():
		return typeHasSet(ty.ElementType())
	case ty.IsTupleType():
		return slices.ContainsFunc(ty.TupleElementTypes(), typeHasSet)
	case ty.IsObjectType():
		for _, at := range ty.AttributeTypes() {
			if typeHasSet(at) {
				return true
			}
		}
	}
	return false
}

// formatBound bounds the output of formatting f once when no argument is larger than largest:
// f itself, every width and precision, and each verb printing the largest argument escaped.
// The result saturates just above maxFunctionValueSize.
func formatBound(f string, largest int) int {
	const limit = maxFunctionValueSize + 1
	out := min(len(f), limit)
	for i := 0; i < len(f) && out < limit; i++ {
		if f[i] != '%' {
			continue
		}
		i++
		if i < len(f) && f[i] == '%' {
			continue
		}
		// Flags, argument indexes, widths and precisions, up to the verb letter.
		num := 0
		for ; i < len(f); i++ {
			c := f[i]
			if c >= '0' && c <= '9' {
				num = min(num*10+int(c-'0'), limit)
				continue
			}
			out, num = min(out+num, limit), 0
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				break
			}
		}
		out = min(out+num+saturatingMul(largest, jsonEscapeFactor), limit)
	}
	return out
}

// saturatingMul returns a*b for non-negative a and b, or maxFunctionWork+1 if that is larger.
func saturatingMul(a, b int) int {
	const limit = maxFunctionWork + 1
	if a == 0 || b == 0 {
		return 0
	}
	if a > limit/b {
		return limit
	}
	return min(a*b, limit)
}

// isJSON reports whether expr comes from a .tf.json file.
func isJSON(expr hcl.Expression) bool {
	return strings.HasSuffix(expr.Range().Filename, ".json")
}
