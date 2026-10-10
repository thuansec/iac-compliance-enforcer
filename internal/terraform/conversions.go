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
	w.unifyAt(types, 1)
}

// unifyAt charges unifying types at nesting depth: cty compares each unified type with the
// types it came from at every level (Type.Equals), so a type is walked once per level above it
// (T-0114f: unifying two equal types doubled 18 times took 0.7 s).
func (w *unifyWalk) unifyAt(types []cty.Type, depth int) {
	if len(types) == 0 || w.over() {
		return
	}
	w.walked += saturatingMul(len(types), depth)
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
			w.unifyAt(column(types, func(ty cty.Type) cty.Type { return ty.TupleElementTypes()[i] }), depth+1)
		}
	case objects == len(types) && sameAttributes(types):
		for name := range types[0].AttributeTypes() {
			w.unifyAt(column(types, func(ty cty.Type) cty.Type { return ty.AttributeType(name) }), depth+1)
		}
	default:
		// Tuples of different lengths, objects with different attributes, collections, or a
		// mix of them: cty unifies all their element types together (or fails).
		w.unifyAt(childTypes(types), depth+1)
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

// conversionCost is the work of converting v to want, as cty does (ADR 0029, ADR 0032), in the
// units of unifyWalk, following cty's conversion path for the value and the target together
// (convert): conversions that unify nothing cost nothing, such as a tuple into a set of strings
// or an object into a map of strings. With defaults (a type constraint with optional attributes),
// typeexpr also unifies the elements of every list, set and map it rebuilds, attribute by
// attribute: each costs k × k / unifyWorkDivisor per attribute of the constraint's widest
// object, plus one. The values and types walked are added once there is a cost. It stops
// counting past limit, and a value that takes more than limit steps to walk costs more.
func conversionCost(v cty.Value, want cty.Type, defaults bool, limit int) int {
	w := &unifyWalk{limit: limit}
	if want != cty.DynamicPseudoType && typeHasDynamic(want) {
		// cty builds the conversion from the types before it touches a value, unifying to find
		// every element type a dynamic target leaves open, even where no value reaches it (an
		// empty list, a target attribute a map lacks): charged as ADR 0029 did.
		w.typeConversions(v.Type())
	}
	w.convert(v, want)
	if defaults {
		w.defaults(v, 1+widestObject(want))
	}
	if w.over() {
		return limit + 1
	}
	return w.total()
}

// convert charges converting v to want as cty's convert package does:
//   - nothing when want is the dynamic type or v already has type want (the type-level work
//     for targets holding the dynamic type is charged by conversionCost);
//   - an unknown or null value is converted from its type alone (replace);
//   - a tuple converted to a list or set of any first unifies its element types to find the
//     element type; each element is then converted to that type (charged as valuePart, since
//     the type is not known here), and for a list the converted elements are unified again;
//   - a tuple converted to a list or set of a known element type converts each element, and for
//     a list unifies the converted elements: n copies of that type, or, when it holds the
//     dynamic type, the elements' own types (converted);
//   - an object converted to a map of any unifies its attribute types first, and again after
//     converting when they are not all primitive; to a map of a known element type it converts
//     each attribute, then unifies them when that type is a collection or an object;
//   - a map converted to a map converts each element, then unifies them when the element type
//     is a collection or an object;
//   - tuples, objects, lists and sets converted to their own kinds convert element by element.
func (w *unifyWalk) convert(v cty.Value, want cty.Type) {
	if w.over() {
		return
	}
	w.walked++
	val, _ := v.Unmark()
	ty := val.Type()
	if want == cty.DynamicPseudoType || ty.Equals(want) {
		return
	}
	if !val.IsKnown() || val.IsNull() {
		w.replace(ty, want)
		return
	}
	compound := func(t cty.Type) bool { return t.IsCollectionType() || t.IsObjectType() }
	// converted charges unifying the converted elements: all of type ety, unless ety holds the
	// dynamic type, which leaves each element its own type; then their own types are unified,
	// as estimated from the elements before conversion (T-0114g review).
	converted := func(ety cty.Type) {
		if typeHasDynamic(ety) {
			w.unify(elementTypes(val))
			return
		}
		w.unify(slices.Repeat([]cty.Type{ety}, val.LengthInt()))
	}
	switch {
	case ty.IsTupleType() && (want.IsListType() || want.IsSetType()):
		ety, types := want.ElementType(), elementTypes(val)
		if ety == cty.DynamicPseudoType {
			w.unify(types)
			w.eachElement(val, w.valuePart)
			if want.IsListType() {
				w.unify(types)
			}
			return
		}
		w.eachElement(val, func(e cty.Value) { w.convert(e, ety) })
		if want.IsListType() {
			converted(ety)
		}
	case ty.IsTupleType() && want.IsTupleType():
		if wants := want.TupleElementTypes(); len(wants) == val.LengthInt() {
			i := 0
			w.eachElement(val, func(e cty.Value) { w.convert(e, wants[i]); i++ })
		}
	case ty.IsObjectType() && want.IsMapType():
		ety, types := want.ElementType(), elementTypes(val)
		if ety == cty.DynamicPseudoType {
			w.unify(types)
			w.eachElement(val, w.valuePart)
			if slices.ContainsFunc(types, func(t cty.Type) bool { return !t.IsPrimitiveType() }) {
				w.unify(types)
			}
			return
		}
		w.eachElement(val, func(e cty.Value) { w.convert(e, ety) })
		if compound(ety) {
			converted(ety)
		}
	case ty.IsMapType() && want.IsMapType():
		ety := want.ElementType()
		w.eachElement(val, func(e cty.Value) { w.convert(e, ety) })
		if compound(ety) {
			converted(ety)
		}
	case (ty.IsObjectType() || ty.IsMapType()) && want.IsObjectType():
		for name, at := range want.AttributeTypes() {
			switch {
			case ty.IsObjectType() && ty.HasAttribute(name):
				w.convert(val.GetAttr(name), at)
			case ty.IsMapType() && val.HasIndex(cty.StringVal(name)).True():
				w.convert(val.Index(cty.StringVal(name)), at)
			}
		}
	case (ty.IsListType() || ty.IsSetType()) && (want.IsListType() || want.IsSetType()):
		ety := want.ElementType()
		w.eachElement(val, func(e cty.Value) { w.convert(e, ety) })
	}
}

// replace charges the type cty gives an unknown or null value converted to want
// (convert.dynamicReplace): it unifies a tuple's element types for a list or set, and an
// object's attribute types for a map, whatever the target element type.
func (w *unifyWalk) replace(in, want cty.Type) {
	if w.over() || in == cty.DynamicPseudoType || want == cty.DynamicPseudoType || want.IsPrimitiveType() {
		return
	}
	w.walked++
	switch {
	case want.IsMapType() && in.IsMapType():
		w.replace(in.ElementType(), want.ElementType())
	case want.IsMapType() && in.IsObjectType(), (want.IsListType() || want.IsSetType()) && in.IsTupleType():
		children := childTypes([]cty.Type{in})
		w.unify(children)
		for _, c := range children {
			w.replace(c, want.ElementType())
		}
	case (want.IsListType() || want.IsSetType()) && (in.IsListType() || in.IsSetType()):
		w.replace(in.ElementType(), want.ElementType())
	case want.IsObjectType() && in.IsMapType():
		for _, at := range want.AttributeTypes() {
			w.replace(in.ElementType(), at)
		}
	case want.IsObjectType() && in.IsObjectType():
		for name, at := range want.AttributeTypes() {
			if in.HasAttribute(name) {
				w.replace(in.AttributeType(name), at)
			}
		}
	case want.IsTupleType() && in.IsTupleType():
		ins := in.TupleElementTypes()
		for i, et := range want.TupleElementTypes() {
			if i < len(ins) {
				w.replace(ins[i], et)
			}
		}
	}
}

// eachElement calls f with each element of the known collection, tuple or object v.
func (w *unifyWalk) eachElement(v cty.Value, f func(cty.Value)) {
	for it := v.ElementIterator(); it.Next() && !w.over(); {
		_, e := it.Element()
		f(e)
	}
}

// valuePart charges converting v to a type the walk does not know (a unified type), counting
// as if every tuple, object or map value in v were converted to a collection: each costs
// unifying its element types (ADR 0029). It can only over-count.
func (w *unifyWalk) valuePart(v cty.Value) {
	stack := []cty.Value{v}
	for len(stack) > 0 && !w.over() {
		val, _ := stack[len(stack)-1].Unmark()
		stack = stack[:len(stack)-1]
		w.walked++
		ty := val.Type()
		if !val.IsKnown() || val.IsNull() {
			continue
		}
		switch {
		case ty.IsTupleType() || ty.IsObjectType() || ty.IsMapType():
			w.unify(elementTypes(val))
		case !ty.IsListType() && !ty.IsSetType():
			continue
		}
		for it := val.ElementIterator(); it.Next(); {
			_, e := it.Element()
			stack = append(stack, e)
		}
	}
}

// defaults charges typeexpr unifying the elements of every list, set and map in v while it
// applies optional-attribute defaults, columns comparisons per pair.
func (w *unifyWalk) defaults(v cty.Value, columns int) {
	stack := []cty.Value{v}
	for len(stack) > 0 && !w.over() {
		val, _ := stack[len(stack)-1].Unmark()
		stack = stack[:len(stack)-1]
		w.walked++
		ty := val.Type()
		if !val.IsKnown() || val.IsNull() {
			continue
		}
		switch {
		case ty.IsCollectionType():
			w.add(saturatingMul(pairs(val.LengthInt()), columns))
		case !ty.IsTupleType() && !ty.IsObjectType():
			continue
		}
		for it := val.ElementIterator(); it.Next(); {
			_, e := it.Element()
			stack = append(stack, e)
		}
	}
}

// conservativeCost is the work of converting v to a type that is not known yet, as coalesce
// converts its arguments to their unified type: every tuple and object type in v unified
// (typeConversions) and every tuple, object or map value (valuePart).
func conservativeCost(v cty.Value, limit int) int {
	w := &unifyWalk{limit: limit}
	w.typeConversions(v.Type())
	w.valuePart(v)
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

// valueConversionCost is the work of converting v to a type unified with another, beyond the
// unification itself (valuePart).
func valueConversionCost(v cty.Value, limit int) int {
	w := &unifyWalk{limit: limit}
	w.valuePart(v)
	if w.over() {
		return limit + 1
	}
	return w.total()
}

// unifyTypesCost is the work of unifying types together, as coalesce does with its arguments'
// and a conditional with its results': the sorts, and the walk even when nothing is sorted, since
// unifying equal types still walks them (T-0114f).
func unifyTypesCost(types []cty.Type, limit int) int {
	w := &unifyWalk{limit: limit}
	w.unify(types)
	if w.over() {
		return limit + 1
	}
	return min(w.cost+w.walked, maxFunctionWork+1)
}

// typeSize counts the types in ty expanded, as cty walks it when it compares or unifies types: a
// type used in several places counts each time, so a type built by repeating another can be far
// larger than any value of it (T-0114f). It stops counting past limit, and a type nested deeper
// than depth counts limit + 1.
func typeSize(ty cty.Type, limit, depth int) int {
	type item struct {
		ty    cty.Type
		depth int
	}
	n := 0
	stack := []item{{ty: ty}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n++
		if n > limit || it.depth > depth {
			return limit + 1
		}
		t, d := it.ty, it.depth+1
		switch {
		case t.IsTupleType():
			for _, et := range t.TupleElementTypes() {
				stack = append(stack, item{et, d})
			}
		case t.IsObjectType():
			for _, at := range t.AttributeTypes() {
				stack = append(stack, item{at, d})
			}
		case t.IsCollectionType():
			stack = append(stack, item{t.ElementType(), d})
		}
		if n+len(stack) > limit {
			return limit + 1 // every type pushed counts at least one
		}
	}
	return n
}
