package terraform

import (
	"slices"

	"github.com/zclconf/go-cty/cty"
)

// Converting a value to a collection type makes cty unify element types, and unifying n types
// sorts them with a comparison of every pair, quadratic in n: tolist over 20,000 elements took
// 9.8 s, and a list(any) variable default as long 4.7 s (T-0114c review). iace charges that
// work to the module's function work before it converts, wherever it converts (ADR 0029):
// function arguments (conversionWork), lookup's default, and variable values converted to their
// type constraints (chargeConversion).

// unifyWalk estimates the work of cty's unification (convert.unify), following its rules:
// unifying k types sorts them, comparing every pair; tuples of one length unify column by
// column, and tuples of different lengths, as a list, by unifying all their element types
// together; objects likewise by attribute names; collections of one kind by their element types;
// a dynamic type among tuples, objects or collections ends it. Each sort of k types costs
// k × k / unifyWorkDivisor (about 6 ns per pair, against about 100 ns per unit of function
// work), charged at every step, and for mixed types times the size of the largest, so the
// estimate only over-counts. The walk stops once the cost or the
// types walked pass limit.
type unifyWalk struct {
	limit, cost, walked int
}

// over reports whether the walk has passed its limit.
func (w *unifyWalk) over() bool {
	return w.cost > w.limit || w.walked > w.limit
}

// add charges n.
func (w *unifyWalk) add(n int) {
	w.cost = min(w.cost+n, maxFunctionWork+1)
}

// total is the cost, plus the values and types walked once there is a cost.
func (w *unifyWalk) total() int {
	if w.cost == 0 {
		return 0
	}
	return min(w.cost+w.walked, maxFunctionWork+1)
}

// unifyWorkDivisor converts pairs of types compared into function work: unifying costs about
// 6 ns per pair, against about 100 ns per unit of function work (T-0114c).
const unifyWorkDivisor = 16

// pairs is the cost of sorting k types.
func pairs(k int) int {
	return saturatingMul(k, k/unifyWorkDivisor)
}

// unify charges unifying types, recursively as cty does.
func (w *unifyWalk) unify(types []cty.Type) {
	if len(types) == 0 || w.over() {
		return
	}
	w.walked += len(types)
	w.add(pairs(len(types)))
	var tuples, objects, lists, sets, maps, dynamic int
	for _, ty := range types {
		switch {
		case ty.IsTupleType():
			tuples++
		case ty.IsObjectType():
			objects++
		case ty.IsListType():
			lists++
		case ty.IsSetType():
			sets++
		case ty.IsMapType():
			maps++
		case ty == cty.DynamicPseudoType:
			dynamic++
		}
	}
	structural := tuples + objects + lists + sets + maps
	switch {
	case structural == 0:
		return // primitive types: the sort is all
	case structural+dynamic < len(types):
		// Mixed types: cty sorts them, comparing tuples of one length and objects with the
		// same attributes element by element, then tries each in turn as the result,
		// comparing it with or converting every type: each pair costs up to the size of the
		// largest type (T-0114d review: 4,096 tuples of 64 numbers and a string took 13 s).
		w.add(saturatingMul(pairs(len(types)), w.largestType(types)))
		return
	case dynamic > 0:
		return // cty unifies to the dynamic type
	case tuples == len(types) && sameLength(types):
		for i := range types[0].TupleElementTypes() {
			w.unify(column(types, func(ty cty.Type) cty.Type { return ty.TupleElementTypes()[i] }))
		}
	case objects == len(types) && sameAttributes(types):
		for name := range types[0].AttributeTypes() {
			w.unify(column(types, func(ty cty.Type) cty.Type { return ty.AttributeType(name) }))
		}
	default:
		// Tuples of different lengths, objects with different attributes, collections, or a
		// mix of them: cty unifies all their element types together (or fails).
		w.unify(childTypes(types))
	}
}

// largestType is the number of types in the largest of types, counted towards the walk.
func (w *unifyWalk) largestType(types []cty.Type) int {
	largest := 0
	for _, ty := range types {
		n := 0
		stack := []cty.Type{ty}
		for len(stack) > 0 && !w.over() {
			t := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			n++
			w.walked++
			stack = append(stack, childTypes([]cty.Type{t})...)
		}
		largest = max(largest, n)
	}
	return largest
}

// childTypes lists the element types of tuples and collections and the attribute types of
// objects in types.
func childTypes(types []cty.Type) []cty.Type {
	var out []cty.Type
	for _, ty := range types {
		switch {
		case ty.IsTupleType():
			out = append(out, ty.TupleElementTypes()...)
		case ty.IsObjectType():
			for _, at := range ty.AttributeTypes() {
				out = append(out, at) // the order changes no cost
			}
		case ty.IsCollectionType():
			out = append(out, ty.ElementType())
		}
	}
	return out
}

// column returns get(ty) for each of types.
func column(types []cty.Type, get func(cty.Type) cty.Type) []cty.Type {
	out := make([]cty.Type, len(types))
	for i, ty := range types {
		out[i] = get(ty)
	}
	return out
}

// sameLength reports whether the tuple types all have the same length.
func sameLength(types []cty.Type) bool {
	n := len(types[0].TupleElementTypes())
	return !slices.ContainsFunc(types, func(ty cty.Type) bool {
		return len(ty.TupleElementTypes()) != n
	})
}

// sameAttributes reports whether the object types all have the same attribute names.
func sameAttributes(types []cty.Type) bool {
	first := types[0].AttributeTypes()
	for _, ty := range types[1:] {
		attrs := ty.AttributeTypes()
		if len(attrs) != len(first) {
			return false
		}
		for name := range attrs {
			if _, ok := first[name]; !ok {
				return false
			}
		}
	}
	return true
}

// typeConversions charges what cty decides from ty alone when it converts a value of type ty to
// a type holding the dynamic type: it unifies the element types of every tuple and the attribute
// types of every object in ty, each on its own, to find the target element type.
func (w *unifyWalk) typeConversions(ty cty.Type) {
	stack := []cty.Type{ty}
	for len(stack) > 0 && !w.over() {
		t := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		w.walked++
		children := childTypes([]cty.Type{t})
		if t.IsTupleType() || t.IsObjectType() {
			w.unify(children)
		}
		stack = append(stack, children...)
	}
}

// conversionCost is the work of converting v to want, as cty does (ADR 0029), in the units of
// unifyWalk:
//   - each known tuple, object or map value in v costs unifying its element types: cty converts
//     every value nested in v on its own, and unifies the elements of a tuple converted to a
//     list, of an object converted to a map, and of a map whose elements it converts;
//   - when want holds the dynamic type (any), cty first unifies the element types of every tuple
//     and object type in v to find the target element type (typeConversions);
//   - with defaults (a type constraint with optional attributes), typeexpr also unifies the
//     elements of every list, set and map it rebuilds, attribute by attribute: each costs k × k
//     / unifyWorkDivisor per attribute of the constraint's widest object, plus one.
//
// The values and types walked are added once there is a cost. The cost over-counts where cty
// does not unify (a tuple converted to a set of strings, an object to a map of strings:
// T-0114g). It stops counting past limit, and a value that takes more than limit steps to walk
// costs more.
func conversionCost(v cty.Value, want cty.Type, defaults bool, limit int) int {
	w := &unifyWalk{limit: limit}
	if typeHasDynamic(want) {
		w.typeConversions(v.Type())
	}
	columns := 1
	if defaults {
		columns += widestObject(want)
	}
	stack := []cty.Value{v}
	for len(stack) > 0 && !w.over() {
		val, _ := stack[len(stack)-1].Unmark()
		stack = stack[:len(stack)-1]
		w.walked++
		ty := val.Type()
		if !val.IsKnown() || val.IsNull() {
			continue // converted from its type alone, charged above when that unifies
		}
		switch {
		case ty.IsTupleType() || ty.IsObjectType() || ty.IsMapType():
			w.unify(elementTypes(val))
			if defaults && ty.IsMapType() {
				w.add(saturatingMul(pairs(val.LengthInt()), columns))
			}
		case ty.IsListType() || ty.IsSetType():
			if defaults {
				w.add(saturatingMul(pairs(val.LengthInt()), columns))
			}
		default:
			continue
		}
		for it := val.ElementIterator(); it.Next(); {
			_, e := it.Element()
			stack = append(stack, e)
		}
	}
	if w.over() {
		return limit + 1
	}
	return w.total()
}

// elementTypes lists the types of v's elements, in order.
func elementTypes(v cty.Value) []cty.Type {
	types := make([]cty.Type, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		types = append(types, e.Type())
	}
	return types
}

// widestObject is the largest attribute count of an object type in ty.
func widestObject(ty cty.Type) int {
	widest := 0
	stack := []cty.Type{ty}
	for len(stack) > 0 {
		t := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if t.IsObjectType() {
			widest = max(widest, len(t.AttributeTypes()))
		}
		stack = append(stack, childTypes([]cty.Type{t})...)
	}
	return widest
}

// typeHasCollection reports whether ty is or holds a list, set or map type: converting to it
// can unify.
func typeHasCollection(ty cty.Type) bool {
	switch {
	case ty.IsCollectionType():
		return true
	case ty.IsTupleType():
		return slices.ContainsFunc(ty.TupleElementTypes(), typeHasCollection)
	case ty.IsObjectType():
		for _, at := range ty.AttributeTypes() {
			if typeHasCollection(at) {
				return true
			}
		}
	}
	return false
}

// typeHasDynamic reports whether ty is or holds the dynamic pseudo-type.
func typeHasDynamic(ty cty.Type) bool {
	switch {
	case ty == cty.DynamicPseudoType:
		return true
	case ty.IsCollectionType():
		return typeHasDynamic(ty.ElementType())
	case ty.IsTupleType():
		return slices.ContainsFunc(ty.TupleElementTypes(), typeHasDynamic)
	case ty.IsObjectType():
		for _, at := range ty.AttributeTypes() {
			if typeHasDynamic(at) {
				return true
			}
		}
	}
	return false
}

// valueConversionCost is the work of converting v to a type unified with another, beyond the
// unification itself: cty converts each nested value on its own and unifies the elements of each
// tuple, object or map it converts (conversionCost to a type without the dynamic type).
func valueConversionCost(v cty.Value, limit int) int {
	return conversionCost(v, cty.String, false, limit)
}

// unifyTypesCost is the work of unifying types together, as coalesce does with its arguments'.
func unifyTypesCost(types []cty.Type, limit int) int {
	w := &unifyWalk{limit: limit}
	w.unify(types)
	if w.over() {
		return limit + 1
	}
	return w.total()
}
