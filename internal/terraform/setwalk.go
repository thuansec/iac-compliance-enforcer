package terraform

import (
	"math/bits"

	"github.com/zclconf/go-cty/cty"
)

// Walking sets (T-0116d): cty sorts a set every time it is iterated, n × log2(n) comparisons,
// each walking both elements for marks and, for compound elements, hashing both
// (setRules.Less). Any walk of a set pays that, a measurement of its size included: six
// `length(var.s)` locals over a set of 8,000 seven-string tuples took 14.4 s, each walk of it
// about 0.4 s, while the set's size is 144,000 units.

// valueSizeWalk is valueSize, plus the sort work of every set it walks: per set of n elements,
// log2(n) × (n × base + the size of its elements / divisor), where compound elements (each sort
// comparison hashes both) cost a base of setSortWork per element and their full size, and
// primitives (compared directly) primitiveSortWork and an eighth of their size: a timing sweep
// of sets of strings, tuples, objects, integers and non-integers (1,000 to 8,000 elements,
// ADR 0036) measured 67 to 154 ns per unit. Before it iterates a set it
// estimates that sort from the set's length and element type, a lower bound of its charge, and
// refuses when the estimate alone passes work, the function work the caller has left: iterating
// is what sorts, so a set that cannot be afforded is never iterated. It refuses too once the sort
// work passes work. A refusal for sorting reports a size past limit and a sort past work, so
// callers that only read the size still treat the value as too large.
func valueSizeWalk(v cty.Value, limit, work, depth int) (size, sort int, ok bool) {
	size, sort, _, ok = valueMarksWalk(v, limit, work, depth)
	return size, sort, ok
}

// valueMarksWalk is valueSizeWalk, also reporting whether v contains a marked value, as
// ContainsMarked does, from the same walk: ContainsMarked walks v again, sorting every set in it
// (0.8 s for a set of 12,000 tuples, T-0116d). A walk that stops before the end reports marked,
// since a mark may lie in what it did not reach (fail closed).
func valueMarksWalk(v cty.Value, limit, work, depth int) (size, sort int, marked, ok bool) {
	type item struct {
		val   cty.Value
		depth int
	}
	// open is a set whose elements are being walked: its subtree ends when the stack is back
	// to below.
	type open struct {
		below, start, n, base, divisor, numbers int
		sortStart                               int  // sort before its elements were walked
		nested                                  bool // its elements can hold sets
	}
	var sets []open
	closeSets := func(stackLen int) {
		for len(sets) > 0 && sets[len(sets)-1].below >= stackLen {
			o := sets[len(sets)-1]
			sets = sets[:len(sets)-1]
			levels := bits.Len(uint(o.n))
			w := saturatingMul(levels, saturatingMul(o.n, o.base)+(size-o.start)/o.divisor+o.numbers)
			if o.nested {
				// Each comparison hashes both elements, sorting every set inside them again.
				w = min(w+saturatingMul(saturatingMul(levels, nestedSortFactor), sort-o.sortStart), maxFunctionWork+1)
			}
			sort = min(sort+w, maxFunctionWork+1)
		}
	}
	stack := []item{{val: v}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.depth > depth {
			return size, sort, true, false
		}
		val, marks := it.val.Unmark()
		marked = marked || len(marks) > 0
		size++
		ty := val.Type()
		switch {
		case !val.IsKnown() || val.IsNull():
			// As large as its type: cty walks the type, which can be far larger than any
			// value built from unknowns (T-0114f).
			// size is at most limit here, so a type that does not fit takes size past it.
			size += typeSize(ty, limit-size+1, depth-it.depth) - 1
		case ty.IsCollectionType() && val.LengthInt() == 0:
			size += typeSize(ty.ElementType(), limit-size, depth-it.depth-1)
		case ty == cty.String:
			size += len(val.AsString())
		case ty == cty.Number:
			size += numberDigits(val)
		case ty.IsCollectionType() || ty.IsObjectType() || ty.IsTupleType():
			if ty.IsSetType() {
				n, ety := val.LengthInt(), ty.ElementType()
				base, divisor := primitiveSortWork, primitiveSortDivisor
				if !ety.IsPrimitiveType() {
					base, divisor = setSortWork, 1
				}
				// Bounded by work too: perElement past it refuses anyway.
				perElement := base + typeSize(ety, min(work, limit), depth-it.depth-1)/divisor
				if saturatingMul(saturatingMul(n, bits.Len(uint(n))), perElement) > work {
					return limit + 1, work + 1, true, false
				}
				sets = append(sets, open{
					below: len(stack), start: size, n: n, base: base, divisor: divisor,
					sortStart: sort, nested: typeHasSet(ety),
				})
			}
			for elems := val.ElementIterator(); elems.Next(); {
				k, ev := elems.Element()
				if ty.IsSetType() && ty.ElementType() == cty.Number {
					o := &sets[len(sets)-1]
					o.numbers = min(o.numbers+nonIntegerSortWork(ev), maxFunctionWork+1)
				}
				// A set's keys are its elements, which may be unknown or marked.
				if k, _ := k.Unmark(); k.Type() == cty.String && k.IsKnown() && !k.IsNull() {
					size += len(k.AsString())
				}
				stack = append(stack, item{val: ev, depth: it.depth + 1})
				if size+len(stack) > limit {
					return size + len(stack), sort, true, false
				}
			}
		}
		if size > limit {
			return size, sort, true, false
		}
		if len(sets) > 0 {
			closeSets(len(stack))
			if sort > work {
				return limit + 1, sort, true, false
			}
		}
	}
	return size, sort, marked, true
}

// elementSortWork is the work of one element of a set per level of its sort, as valueSizeWalk
// charges it (ADR 0036), for an element whose size is size: compound elements setSortWork plus
// their size, primitives primitiveSortWork plus an eighth of it, and non-integer numbers their
// decimal comparisons too. A timing sweep of sets built from 1,000 to 5,000 tuples measured 69
// to 92 ns per unit (T-0116h).
func elementSortWork(e cty.Value, size int) int {
	if !e.Type().IsPrimitiveType() {
		return min(setSortWork+size, maxFunctionWork+1)
	}
	work := primitiveSortWork + size/primitiveSortDivisor
	if e.Type() == cty.Number {
		work += nonIntegerSortWork(e)
	}
	return work
}

// elementSortFloor is elementSortWork's least value for an element of type ety, which bounds a
// set's sort from below before it is iterated, as valueSizeWalk's up-front estimate does:
// a compound element is at least as large as its type (typeSize, counted up to limit).
func elementSortFloor(ety cty.Type, limit int) int {
	if !ety.IsPrimitiveType() {
		return min(setSortWork+typeSize(ety, limit, maxNesting), maxFunctionWork+1)
	}
	return primitiveSortWork
}

// nonIntegerSortWork is the extra work, per level of a sort, of an element of a set of numbers:
// cty compares numbers that are not integers by their exact decimal text, about 20 units, and
// formatting a number with many fractional bits costs its numberFormatCost (a timing sweep of
// sets of 1,000 and 8,000 halves, thirds and 512-bit fractions measured 400 to 940 ns per unit
// without it, as integers measure 130). Integers, unknowns and nulls cost nothing more.
func nonIntegerSortWork(v cty.Value) int {
	v, _ = v.Unmark()
	if !v.IsKnown() || v.IsNull() || v.AsBigFloat().IsInt() {
		return 0
	}
	return nonIntegerCompareWork + numberFormatCost(v)
}

// nestedSortFactor calibrates the sorts of the sets inside a set's elements, per level of its own
// sort: each sort comparison hashes both elements, which iterates, and so sorts, every set in
// them (setRules.Less, makeSetHashBytes).
const nestedSortFactor = 4

// nonIntegerCompareWork calibrates nonIntegerSortWork's fixed part.
const nonIntegerCompareWork = 20

// primitiveSortWork and primitiveSortDivisor calibrate the sort of a set of primitive values in
// a walk, per element and level: a fixed part and a share of the element's size.
const (
	primitiveSortWork    = 2
	primitiveSortDivisor = 8
)
