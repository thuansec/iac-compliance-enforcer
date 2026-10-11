package terraform

import (
	"math/bits"

	"github.com/zclconf/go-cty/cty"
)

// Equality operators (T-0116b): hcl evaluates `a == b` and `a != b` itself, with cty's
// Value.Equals, outside iace's function table, and that can take seconds:
//   - cty compares two sets by looking each element of one up in the other (set.Has), comparing
//     it with every element of its hash. cty hashes a number by its first ten significant
//     digits, so close numbers collide: `var.s == var.s` over 1,000 colliding numbers took 2.7 s.
//   - Equals walks both operands for marks (ContainsMarked) again at every level it recurses
//     into, sorting every set it meets, so nested values multiply the work by their depth: a
//     400-deep tuple around 20,000 strings took 4.5 s per comparison (T-0116b review).
//
// The right operand is wrapped like a conditional's false result (ADR 0033), and the comparison
// is charged with both operands in hand:
//
//	a == b  →  __iace_cond_true(__iace_cond_begin(S), a) == __iace_cmp_right(S, b)
//
// hcl evaluates the left operand first. Over the limit the right operand is a dynamic unknown,
// so the comparison is unknown, and m.cmpLimited makes evalExpr report it and return the whole
// value unknown. Primitive operands, and operands cty tells apart without recursing (unknown,
// null or of different types), are not charged here: hcl's walk of an operator's arguments is
// charged with the expression (walksArguments).
const cmpRightName = "__iace_cmp_right"

// equalityCost bounds the work of a.Equals(b), following cty: every node of both operands is
// walked for marks once per level above it (markWalks), and the elements of every pair of sets
// compared are looked up in the other set (equalityWalk.sets). Both values must have been
// measured, which bounds the walks. It stops counting past limit.
func equalityCost(a, b cty.Value, limit int) int {
	w := &equalityWalk{limit: limit}
	a, _ = a.UnmarkDeep()
	b, _ = b.UnmarkDeep()
	w.add(w.markWalks(a))
	w.add(w.markWalks(b))
	w.equal(a, b)
	return w.cost
}

// equalityWalk counts the work of comparing two values.
type equalityWalk struct {
	limit, cost int
}

func (w *equalityWalk) over() bool { return w.cost > w.limit }

func (w *equalityWalk) add(n int) { w.cost = min(w.cost+n, maxFunctionWork+1) }

// markWalks is marksWalk of v within what is left of the walk's limit.
func (w *equalityWalk) markWalks(v cty.Value) int {
	return marksWalk(v, w.limit-w.cost)
}

// marksWalk is the work of cty's marks walks over v when Equals compares it: Equals calls
// ContainsMarked (a DeepValues walk that allocates a slice of every value) and
// HasWhollyKnownType, each a walk of the whole subtree, at every level it recurses into. So a
// node at depth d is walked d + 1 times (an upper bound: cty stops recursing where the operands
// differ), at markWalkWork per node, and each walk sorts every set it meets (setSort). It counts
// in one pass, stopping past limit. v must have been measured.
func marksWalk(v cty.Value, limit int) int {
	type item struct {
		val   cty.Value
		depth int
	}
	total := 0
	stack := []item{{val: v}}
	for len(stack) > 0 && total <= limit {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node, val := markWalkWork, it.val
		if val.IsKnown() && !val.IsNull() && val.CanIterateElements() {
			ty := val.Type()
			sort := newSetSort(val)
			for elems := val.ElementIterator(); elems.Next(); {
				k, e := elems.Element()
				switch {
				case ty.IsSetType():
					weight, _ := comparisonWeight(e)
					sort.add(e, weight)
				case ty.IsMapType():
					// cty iterates a map's keys in sorted order too, on every walk: a plain
					// string sort, about 300 ns per key and walk for 20,000 keys.
					node += mapKeyWalkWork + len(k.AsString())/16
				}
				stack = append(stack, item{e, it.depth + 1})
			}
			node += sort.total
		}
		total = min(total+saturatingMul(node, it.depth+1), maxFunctionWork+1)
	}
	return total
}

// markWalkWork calibrates marksWalk: two walks per operand at each level, one allocating
// (T-0116b review: deep lists and maps around many strings measured 260 to 310 ns per unit at
// one unit per node).
const markWalkWork = 3

// mapKeyWalkWork is the work of sorting one key of a map in a marks walk, beyond the walk of
// its element (cty sorts a map's keys on every iteration).
const mapKeyWalkWork = 3

// equal charges the set lookups of comparing a and b, which are unmarked, where cty recurses.
func (w *equalityWalk) equal(a, b cty.Value) {
	if w.over() || !a.IsKnown() || !b.IsKnown() || a.IsNull() || b.IsNull() {
		return
	}
	ty := a.Type()
	if !ty.Equals(b.Type()) || !typeHasSet(ty) {
		return // cty returns false, or finds no set below (the walks are charged already)
	}
	switch {
	case ty.IsSetType():
		w.sets(a, b)
	case ty.IsObjectType():
		for name := range ty.AttributeTypes() {
			w.equal(a.GetAttr(name), b.GetAttr(name))
		}
	case ty.IsMapType():
		if a.LengthInt() != b.LengthInt() {
			return
		}
		for it := a.ElementIterator(); it.Next() && !w.over(); {
			k, av := it.Element()
			if b.HasIndex(k).True() {
				w.equal(av, b.Index(k))
			}
		}
	case ty.IsListType() || ty.IsTupleType():
		if a.LengthInt() != b.LengthInt() {
			return
		}
		for ia, ib := a.ElementIterator(), b.ElementIterator(); ia.Next() && ib.Next() && !w.over(); {
			_, av := ia.Element()
			_, bv := ib.Element()
			w.equal(av, bv)
		}
	}
}

// sets charges comparing the sets a and b. Equals iterates each in order, sorting it
// (setSort), and hashes every element (its comparison weight), looking it up among the elements
// of the other set that share its hash. Comparing two elements is a full Equals of them, which
// walks each for marks at every level (marksWalk of the element; a primitive costs its weight):
// compound elements around colliding numbers share a hash, and a set of 40 lists nested 100 deep
// took 4.8 s (T-0116b review). So a bucket with n1 and n2 elements whose comparisons cost m1
// and m2 in total costs n1 × m2 + n2 × m1. Elements that hold sets compare pairwise in turn, so
// a bucket of them costs m1 × m2, except one element on each side, which costs two comparisons
// (2 × (m1 + m2)) plus comparing the sets inside them (equal).
// Distinct values hash apart and cost only the hashing. A product of the sets' sizes
// (setComparisonWork, which contains and index use) would refuse comparing two large sets of
// distinct values, which is linear.
func (w *equalityWalk) sets(a, b cty.Value) {
	type bucket struct {
		n1, n2, m1, m2 int
		e1, e2         cty.Value // the first element on each side
	}
	buckets := map[int]*bucket{}
	for side, s := range []cty.Value{a, b} {
		sort := newSetSort(s)
		for it := s.ElementIterator(); it.Next(); {
			_, e := it.Element()
			weight, _ := comparisonWeight(e)
			sort.add(e, weight)
			w.add(weight)
			if w.over() {
				return
			}
			cmp := weight
			if !e.Type().IsPrimitiveType() {
				cmp = max(cmp, marksWalk(e, w.limit-w.cost))
			}
			h := e.Hash()
			bk := buckets[h]
			if bk == nil {
				bk = &bucket{}
				buckets[h] = bk
			}
			if side == 0 {
				if bk.n1 == 0 {
					bk.e1 = e
				}
				bk.n1, bk.m1 = bk.n1+1, min(bk.m1+cmp, maxFunctionWork+1)
			} else {
				if bk.n2 == 0 {
					bk.e2 = e
				}
				bk.n2, bk.m2 = bk.n2+1, min(bk.m2+cmp, maxFunctionWork+1)
			}
		}
		w.add(sort.total)
	}
	nested := typeHasSet(a.Type().ElementType())
	for _, bk := range buckets {
		switch {
		case nested && bk.n1 == 1 && bk.n2 == 1:
			// Distinct elements hash apart: one Equals each way, which compares the sets
			// inside them in turn (T-0116b review: m1 × m2 refused 200 objects holding small
			// sets, 86 ms of work).
			w.add(min(2*(bk.m1+bk.m2), maxFunctionWork+1))
			w.equal(bk.e1, bk.e2)
		case nested:
			w.add(saturatingMul(bk.m1, bk.m2))
		default:
			w.add(min(saturatingMul(bk.n1, bk.m2)+saturatingMul(bk.n2, bk.m1), maxFunctionWork+1))
		}
	}
}

// setSort counts the work of iterating a set once, element by element as the caller walks it:
// cty sorts the set every time, n × log2(n) comparisons, each walking both elements for marks,
// hashing compound elements and formatting non-integer numbers as exact decimals
// (setRules.Less, RawEquals). Comparing two sets of 4,000 distinct strings took 127 ms, almost
// all of it sorting (T-0116b). Each element is charged, per level of the sort, setSortWork plus
// its comparison weight (times compoundSortFactor for compound elements) plus, for a number,
// its formatting cost again. A value that is not a set counts nothing.
type setSort struct {
	levels, factor, total int
}

// newSetSort starts counting the sort of v, which must have been measured. A value that is not
// a set counts nothing.
func newSetSort(v cty.Value) *setSort {
	if !v.Type().IsSetType() {
		return &setSort{}
	}
	factor := 1
	if !v.Type().ElementType().IsPrimitiveType() {
		factor = compoundSortFactor
	}
	return &setSort{levels: bits.Len(uint(v.LengthInt())), factor: factor}
}

// add counts the element e, of comparison weight weight.
func (s *setSort) add(e cty.Value, weight int) {
	if s.levels == 0 {
		return
	}
	per := setSortWork + saturatingMul(weight, s.factor)
	if e.Type() == cty.Number && e.IsKnown() && !e.IsNull() {
		per += numberFormatCost(e)
	}
	s.total = min(s.total+saturatingMul(per, s.levels), maxFunctionWork+1)
}

// setSortWork and compoundSortFactor calibrate one level of sorting a set, per element: the
// fixed walk of a comparison, and the hashing that compound elements add (a timing sweep of
// strings, numbers and small objects at 100 to 4,000 elements stays near 120 ns per unit).
const (
	setSortWork        = 16
	compoundSortFactor = 6
)
