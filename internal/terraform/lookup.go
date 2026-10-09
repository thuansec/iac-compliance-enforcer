package terraform

import (
	"errors"

	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
)

// lookup reads one element of a map, but as a cty function every call walks the whole map:
// cty checks every argument for marks, and the bounded wrapper measures it. The idiom
// `{ for k in keys(local.m) : k => lookup(local.m, k, null).x }` then costs the map's size per
// key, about 124 ns per unit, and reached a module's function work from about 140 entries
// (T-0113c). So lookup calls in the syntax trees iace evaluates are rewritten (rewriteForExprs)
// to lookupFunctionName, which takes its arguments as expressions, evaluates them itself and
// charges only the value it returns (ADR 0023).

// lookupFunctionName is the internal function lookup calls are rewritten to.
const lookupFunctionName = "__iace_lookup"

// isLookupCall reports whether call is a lookup, as written or rewritten, with the arguments
// lookupFunction takes: two or three, none expanded.
func isLookupCall(call *hclsyntax.FunctionCallExpr) bool {
	switch call.Name {
	case "lookup", "core::lookup", lookupFunctionName:
		return !call.ExpandFinal && (len(call.Args) == 2 || len(call.Args) == 3)
	}
	return false
}

// lookupFunction is lookupFunctionName for m: lookup(map, key[, default]) with Terraform's
// semantics and errors, except that a map whose other elements are unknown still yields its
// known element (Terraform returns unknown at plan; the element is what it resolves to). The
// result keeps the marks of the map and the key.
func (m *ParsedModule) lookupFunction() function.Function {
	if m.lookupFn != nil {
		return *m.lookupFn
	}
	closure := func(name string) function.Parameter {
		return function.Parameter{Name: name, Type: customdecode.ExpressionClosureType}
	}
	f := function.New(&function.Spec{
		Description: "Returns the element of a map or object with the given key, or a default.",
		Params:      []function.Parameter{closure("inputMap"), closure("key")},
		VarParam:    &function.Parameter{Name: "default", Type: customdecode.ExpressionClosureType},
		Type:        function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if len(args) > 3 {
				return cty.NilVal, function.NewArgErrorf(3, "lookup takes at most three arguments")
			}
			vals := make([]cty.Value, len(args))
			for i, a := range args {
				v, diags := customdecode.ExpressionClosureFromVal(a).Value()
				m.forDiags = append(m.forDiags, diags...) // evalExpr returns them, as hcl would
				if diags.HasErrors() {
					return cty.DynamicVal, nil
				}
				vals[i] = v
			}
			result, marks, err := lookupValue(vals)
			if err != nil || !result.IsKnown() {
				return result.WithMarks(marks), err
			}
			n, ok := valueSize(result, maxFunctionWork-m.fnWork, maxNesting)
			if !ok || !m.chargeFunctionWork(1+n) {
				m.spendFunctionWork(n)
				m.fnLimited = true
				return cty.DynamicVal.WithMarks(marks), nil
			}
			return result.WithMarks(marks), nil
		},
	})
	m.lookupFn = &f
	return f
}

// lookupValue is lookup over evaluated arguments: the element, or the default, and the marks
// of the map and the key, which the result carries. Only the top level of the map is unmarked:
// an element keeps its own marks.
func lookupValue(args []cty.Value) (cty.Value, cty.ValueMarks, error) {
	mapVal, mapMarks := args[0].Unmark()
	key, keyMarks := args[1].Unmark()
	marks := make(cty.ValueMarks, len(mapMarks)+len(keyMarks))
	for mark := range mapMarks {
		marks[mark] = struct{}{}
	}
	for mark := range keyMarks {
		marks[mark] = struct{}{}
	}
	// Checks in the order Terraform's lookup makes them, so errors match: nulls, then the types,
	// then whether the values are known.
	if mapVal.IsNull() || key.IsNull() {
		return cty.NilVal, marks, errors.New("the map and the key must not be null")
	}
	ty := mapVal.Type()
	if !ty.IsMapType() && !ty.IsObjectType() && ty != cty.DynamicPseudoType {
		return cty.NilVal, marks, function.NewArgErrorf(0, "the first argument must be a map or an object")
	}
	keyStr, err := convert.Convert(key, cty.String)
	if err != nil {
		return cty.NilVal, marks, function.NewArgErrorf(1, "the key must be a string")
	}
	var dflt *cty.Value
	if len(args) == 3 {
		d := args[2]
		if ty.IsMapType() {
			converted, err := convert.Convert(d, ty.ElementType())
			if err != nil {
				return cty.NilVal, marks, function.NewArgErrorf(2, "the default value must have the same type as the map elements")
			}
			d = converted
		}
		dflt = &d
	}
	if ty.IsObjectType() && keyStr.IsKnown() && !ty.HasAttribute(keyStr.AsString()) && dflt == nil {
		// The object's type decides this, known or not.
		// The key is not quoted: it may be sensitive, and messages never hold values.
		return cty.NilVal, marks, function.NewArgErrorf(1, "the given object has no attribute with this key")
	}
	if !mapVal.IsKnown() || !keyStr.IsKnown() || ty == cty.DynamicPseudoType {
		return cty.DynamicVal, marks, nil
	}
	k := keyStr.AsString()
	switch {
	case ty.IsObjectType() && ty.HasAttribute(k):
		return mapVal.GetAttr(k), marks, nil
	case ty.IsMapType() && mapVal.HasIndex(keyStr).True():
		return mapVal.Index(keyStr), marks, nil
	case dflt != nil:
		return *dflt, marks, nil
	}
	return cty.NilVal, marks, errors.New("the key is not in the map and no default was given")
}

// renameLookup rewrites a lookup call to lookupFunctionName; rewriteForExprs calls it for every
// node of the trees iace evaluates.
func renameLookup(n hclsyntax.Node) {
	if call, ok := n.(*hclsyntax.FunctionCallExpr); ok && isLookupCall(call) {
		call.Name = lookupFunctionName
	}
}

// forFunctionsAnd is forFunctions with lookupFunctionName, for tests that evaluate a rewritten
// tree directly.
func (m *ParsedModule) forFunctionsAnd() map[string]function.Function {
	fns := m.forFunctions()
	fns[lookupFunctionName] = m.lookupFunction()
	return fns
}
