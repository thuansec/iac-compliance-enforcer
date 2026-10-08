package terraform

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Terraform functions whose behavior differs from any go-cty stdlib function. Each follows
// Terraform's documentation and is written for iace (Terraform's source is BUSL-1.1 and is
// never copied). Parameters that do not allow marks make cty mark the result with every mark of
// those arguments, nested marks included: more than Terraform marks (lookup of an unmarked
// attribute next to a sensitive one, for example), which fails closed.

// lengthFunc counts the grapheme clusters of a string, the elements of a collection, or the
// elements or attributes of a tuple or object, which its type gives even when it is unknown.
var lengthFunc = function.New(&function.Spec{
	Description: "Returns the length of a string, collection or structural value.",
	Params: []function.Parameter{{
		Name:             "value",
		Type:             cty.DynamicPseudoType,
		AllowUnknown:     true,
		AllowDynamicType: true,
	}},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		if ty == cty.String || ty == cty.DynamicPseudoType || ty.IsCollectionType() || ty.IsTupleType() || ty.IsObjectType() {
			return cty.Number, nil
		}
		return cty.NilType, function.NewArgErrorf(0, "argument must be a string, a collection type, or a structural type")
	},
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		v := args[0]
		ty := v.Type()
		switch {
		case ty.IsTupleType():
			return cty.NumberIntVal(int64(len(ty.TupleElementTypes()))), nil
		case ty.IsObjectType():
			return cty.NumberIntVal(int64(len(ty.AttributeTypes()))), nil
		case ty == cty.DynamicPseudoType || !v.IsKnown():
			return cty.UnknownVal(cty.Number), nil
		case ty == cty.String:
			return stdlib.Strlen(v)
		default:
			return v.Length(), nil
		}
	},
})

// coalesceFunc returns the first argument that is neither null nor an empty string, converted
// to the arguments' common type. An unknown argument before it makes the result unknown.
var coalesceFunc = function.New(&function.Spec{
	Description: "Returns the first argument that is not null or an empty string.",
	VarParam: &function.Parameter{
		Name:             "vals",
		Type:             cty.DynamicPseudoType,
		AllowNull:        true,
		AllowUnknown:     true,
		AllowDynamicType: true,
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		types := make([]cty.Type, len(args))
		for i, a := range args {
			types[i] = a.Type()
		}
		ty, _ := convert.UnifyUnsafe(types)
		if ty == cty.NilType {
			return cty.NilType, errors.New("all arguments must have the same type")
		}
		return ty, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for _, a := range args {
			v, err := convert.Convert(a, retType)
			if err != nil {
				return cty.NilVal, err
			}
			switch {
			case !v.IsKnown():
				return cty.UnknownVal(retType), nil
			case v.IsNull(), retType == cty.String && v.AsString() == "":
				continue
			}
			return v, nil
		}
		return cty.NilVal, errors.New("no non-null, non-empty-string arguments")
	},
})

// indexFunc returns the position of the first element of a list or tuple equal to a value. An
// unknown comparison before a match makes the result unknown. Marks anywhere in the arguments
// mark the result.
var indexFunc = function.New(&function.Spec{
	Description: "Returns the index of the first element of a list or tuple equal to a value.",
	Params: []function.Parameter{
		{Name: "list", Type: cty.DynamicPseudoType, AllowUnknown: true, AllowDynamicType: true, AllowMarked: true},
		{Name: "value", Type: cty.DynamicPseudoType, AllowUnknown: true, AllowDynamicType: true, AllowMarked: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		if !ty.IsListType() && !ty.IsTupleType() && ty != cty.DynamicPseudoType {
			return cty.NilType, function.NewArgErrorf(0, "argument must be a list or tuple")
		}
		return cty.Number, nil
	},
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		list, listMarks := args[0].UnmarkDeep()
		val, valMarks := args[1].UnmarkDeep()
		unknown := cty.UnknownVal(cty.Number).WithMarks(listMarks, valMarks)
		if !list.IsKnown() || !val.IsKnown() {
			return unknown, nil
		}
		if list.LengthInt() == 0 {
			return cty.NilVal, function.NewArgErrorf(0, "cannot search an empty list")
		}
		for it := list.ElementIterator(); it.Next(); {
			i, el := it.Element()
			eq := el.Equals(val)
			if !eq.IsKnown() {
				return unknown, nil
			}
			if eq.True() {
				return i.WithMarks(listMarks, valMarks), nil
			}
		}
		return cty.NilVal, errors.New("item not found")
	},
})

// lookupFunc returns the element of a map, or the attribute of an object, with the given key.
// A missing key returns the optional default (which may be null, and is converted to a map's
// element type), and is an error without one. A map or key that is not wholly known makes the
// result unknown.
var lookupFunc = function.New(&function.Spec{
	Description: "Returns the element of a map or object with the given key, or a default.",
	Params: []function.Parameter{
		{Name: "inputMap", Type: cty.DynamicPseudoType, AllowUnknown: true},
		{Name: "key", Type: cty.String, AllowUnknown: true},
	},
	VarParam: &function.Parameter{
		Name:             "default",
		Type:             cty.DynamicPseudoType,
		AllowNull:        true,
		AllowUnknown:     true,
		AllowDynamicType: true,
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		if len(args) > 3 {
			return cty.NilType, function.NewArgErrorf(3, "lookup takes at most three arguments")
		}
		ty, key := args[0].Type(), args[1]
		switch {
		case ty == cty.DynamicPseudoType:
			return cty.DynamicPseudoType, nil
		case ty.IsMapType():
			if len(args) == 3 {
				if _, err := convert.Convert(args[2], ty.ElementType()); err != nil {
					return cty.NilType, function.NewArgErrorf(2, "the default value must have the same type as the map elements")
				}
			}
			return ty.ElementType(), nil
		case ty.IsObjectType():
			switch {
			case !key.IsKnown():
				return cty.DynamicPseudoType, nil
			case ty.HasAttribute(key.AsString()):
				return ty.AttributeType(key.AsString()), nil
			case len(args) == 3:
				return args[2].Type(), nil
			}
			return cty.NilType, function.NewArgErrorf(1, "the given object has no attribute %q", key.AsString())
		}
		return cty.NilType, function.NewArgErrorf(0, "the first argument must be a map or an object")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		m, key := args[0], args[1]
		if !m.IsWhollyKnown() || !key.IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		k := key.AsString()
		if m.Type().IsObjectType() {
			if m.Type().HasAttribute(k) {
				return m.GetAttr(k), nil
			}
		} else if m.HasIndex(key).True() {
			return m.Index(key), nil
		}
		if len(args) == 3 {
			return convert.Convert(args[2], retType)
		}
		return cty.NilVal, errors.New("the key is not in the map and no default was given")
	},
})

// stringTestFunc returns a function of two strings that reports test(s, t).
func stringTestFunc(desc, second string, test func(s, t string) bool) function.Function {
	return function.New(&function.Spec{
		Description: desc,
		Params: []function.Parameter{
			{Name: "str", Type: cty.String},
			{Name: second, Type: cty.String},
		},
		Type: function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return cty.BoolVal(test(args[0].AsString(), args[1].AsString())), nil
		},
	})
}

var (
	startsWithFunc  = stringTestFunc("Reports whether a string starts with a prefix.", "prefix", strings.HasPrefix)
	endsWithFunc    = stringTestFunc("Reports whether a string ends with a suffix.", "suffix", strings.HasSuffix)
	strContainsFunc = stringTestFunc("Reports whether a string contains a substring.", "substr", strings.Contains)
)

// base64EncodeFunc encodes a string's UTF-8 bytes with standard Base64.
var base64EncodeFunc = function.New(&function.Spec{
	Description: "Encodes a string's UTF-8 bytes with standard Base64.",
	Params:      []function.Parameter{{Name: "str", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	RefineResult: func(b *cty.RefinementBuilder) *cty.RefinementBuilder {
		return b.NotNull()
	},
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})

// base64DecodeFunc decodes standard Base64, whose result must be UTF-8 text.
var base64DecodeFunc = function.New(&function.Spec{
	Description: "Decodes standard Base64 into a UTF-8 string.",
	Params:      []function.Parameter{{Name: "str", Type: cty.String}},
	Type:        function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		b, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil {
			// The error quotes an offset only; the argument may be sensitive.
			return cty.NilVal, fmt.Errorf("failed to decode base64 data: %w", err)
		}
		if !utf8.Valid(b) {
			return cty.NilVal, errors.New("the result of decoding the provided string is not valid UTF-8")
		}
		return cty.StringVal(string(b)), nil
	},
})
