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
// build sets are left out: cty hashes numbers with ten significant digits, so a set of close
// numbers compares every pair at a cost that grows with their precision.
var supportedFunctions = map[string]function.Function{
	// Terraform's own semantics, implemented in functions_terraform.go
	"base64decode": base64DecodeFunc,
	"base64encode": base64EncodeFunc,
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
	"chunklist":    stdlib.ChunklistFunc,
	"coalescelist": stdlib.CoalesceListFunc,
	"compact":      stdlib.CompactFunc,
	"concat":       stdlib.ConcatFunc,
	"contains":     stdlib.ContainsFunc,
	"element":      stdlib.ElementFunc,
	"flatten":      stdlib.FlattenFunc,
	"keys":         stdlib.KeysFunc,
	"merge":        stdlib.MergeFunc,
	"range":        stdlib.RangeFunc,
	"reverse":      stdlib.ReverseListFunc,
	"slice":        stdlib.SliceFunc,
	"sort":         stdlib.SortFunc,
	"values":       stdlib.ValuesFunc,
	"zipmap":       stdlib.ZipmapFunc,
	// type conversion
	"tobool":   stdlib.MakeToFunc(cty.Bool),
	"tolist":   stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tomap":    stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)),
	"tonumber": stdlib.MakeToFunc(cty.Number),
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
	"contains":   setComparisonCost,
	"format":     formatCost,
	"formatlist": formatListCost,
	"index":      setComparisonCost,
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
			m.fns[name] = m.bounded(f, callCosts[name])
		}
		for name, f := range unboundedFunctions {
			m.fns[name] = f
		}
		for name, f := range m.fileFunctions() {
			m.fns[name] = m.bounded(f, nil)
		}
		m.fns["replace"] = m.bounded(m.replaceFunc(), nil)
		m.fns["regex"] = m.bounded(m.regexFunc(false), nil)
		m.fns["regexall"] = m.bounded(m.regexFunc(true), nil)
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
// sets m.fnLimited so evalExpr reports it. cost, if not nil, bounds f's result. The wrapper
// keeps f's parameters but takes any type: hcl converts arguments to the parameter types
// before a call, and converting a large number to a string, for example, costs as much as the
// number's digits, so the wrapper converts them itself once their size is checked. cty then
// handles unknown, null and marked arguments exactly as for f.
func (m *ParsedModule) bounded(f function.Function, cost callCost) function.Function {
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
	return function.New(&function.Spec{
		Description: f.Description(),
		Params:      params,
		VarParam:    varParam,
		Type: func(args []cty.Value) (cty.Type, error) {
			conv, _, ok, err := convertArgs(f, args, m.functionArgsLimit())
			if err != nil || !ok {
				return cty.DynamicPseudoType, err
			}
			return f.ReturnTypeForValues(conv)
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
			conv, sizes, ok, err := convertArgs(f, args, argsLimit)
			if err != nil {
				return cty.NilVal, err
			}
			total := 0
			for _, n := range sizes {
				total += n
			}
			if !ok {
				// Measuring stopped at argsLimit; a refused call still spends that work, so
				// refused calls cannot repeat for free.
				m.spendFunctionWork(argsLimit)
				return limited()
			}
			out, work := 0, 0
			if cost != nil {
				out, work = cost(conv, sizes)
			}
			if out > maxFunctionValueSize || !m.chargeFunctionWork(total, work) {
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

// functionArgsLimit is the largest total argument size a call may have: maxFunctionValueSize,
// or less once the module's work budget runs low, so that calls stop measuring arguments when
// it is spent.
func (m *ParsedModule) functionArgsLimit() int {
	return min(maxFunctionValueSize, maxFunctionWork-m.fnWork)
}

// convertArgs measures args, which together may not pass limit, and then converts each to the
// type of f's parameter, as hcl would before calling f. ok is false when the arguments are too
// large; nothing is converted then.
func convertArgs(f function.Function, args []cty.Value, limit int) (conv []cty.Value, sizes []int, ok bool, err error) {
	sizes = make([]int, len(args))
	total := 0
	for i, a := range args {
		n, ok := valueSize(a, limit-total, maxNesting)
		if !ok {
			return nil, sizes, false, nil
		}
		sizes[i] = n
		total += n
	}
	params, varParam := f.Params(), f.VarParam()
	conv = make([]cty.Value, len(args))
	for i, a := range args {
		var ty cty.Type
		switch {
		case i < len(params):
			ty = params[i].Type
		case varParam != nil:
			ty = varParam.Type
		default:
			return nil, sizes, false, function.NewArgErrorf(i, "too many arguments")
		}
		if conv[i], err = convert.Convert(a, ty); err != nil {
			return nil, sizes, false, function.NewArgError(i, err)
		}
	}
	return conv, sizes, true, nil
}

// chargeFunctionWork adds work to the module's function work, unless that would pass
// maxFunctionWork. Each amount is at most maxFunctionWork, so the sum cannot overflow.
func (m *ParsedModule) chargeFunctionWork(amounts ...int) bool {
	sum := 0
	for _, n := range amounts {
		sum += min(n, maxFunctionWork+1)
	}
	if sum > maxFunctionWork-m.fnWork {
		return false
	}
	m.fnWork += sum
	return true
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

// setComparisonCost charges the pairwise work of comparing values that hold sets, for
// functions that compare elements of a collection with a value (contains, index). cty compares
// two sets by looking up each element of one in the other, and when number hashes collide
// (cty hashes ten significant digits) each lookup compares every element: the work is bounded
// by the product of the sizes. Values without sets compare in linear time.
func setComparisonCost(args []cty.Value, sizes []int) (out, work int) {
	if len(args) < 2 || !typeHasSet(args[0].Type()) && !typeHasSet(args[1].Type()) {
		return 0, 0
	}
	return 0, saturatingMul(sizes[0], sizes[1])
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
