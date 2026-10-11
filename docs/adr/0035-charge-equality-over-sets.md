# 0035 · Charge equality operators over sets and nested values

- Status: accepted
- Date: 2026-10-11
- Task: T-0116b
- Extends: ADR 0033

## Context
hcl evaluates `==` and `!=` itself, with cty's Value.Equals, so iace's function table never sees
them. cty compares two sets by iterating each and looking every element up in the other
(set.Has). A lookup compares the element with every element sharing its hash. cty hashes a
number by its first ten significant digits, so close numbers collide, and `var.s == var.s` over
1,000 colliding numbers took 2.7 s (1,500 took 14 s). Iterating a set also sorts it, every
time, and each sort comparison walks both elements for marks: two sets of 4,000 distinct
strings compare in 127 ms, almost all of it sorting. Equals also walks both operands for marks
(ContainsMarked) again at every level it recurses into, sorting every set it meets, so nested
values multiply the work by their depth, with or without sets: a 400-deep tuple around 20,000
strings took 4.5 s per comparison, and a 400-deep list around a set of 2,000 strings 22 s
(T-0116b review).

## Decision
- The rewrite wraps both operands of `==` and `!=`, like a conditional's results (ADR 0033):
  `a == b` becomes `__iace_cond_true(__iace_cond_begin(S), a) == __iace_cmp_right(S, b)`. hcl
  evaluates the left operand first, so the right wrapper sees both. The operands travel as
  capsules, so cty walks nothing extra and hcl's semantics hold: values, unknowns, nulls,
  marks, refinements and errors are unchanged.
- The right wrapper charges whenever cty recurses: both operands are known, not null, of the
  same type, and that type is not primitive. Comparisons of primitive values, and those cty
  decides at once, cost nothing more. It charges both operands' sizes, then equalityCost:
  - marks walks: every node of both operands, times its depth plus one, at markWalkWork (3)
    per node, since each level walks it twice (ContainsMarked through DeepValues, which
    allocates, and HasWhollyKnownType). A map adds mapKeyWalkWork (3) per key, because cty sorts
    its keys on every walk. A set adds its sort: per element and level of the sort (log2 of the
    length), setSortWork (16) and its weight, six times the weight for compound elements, whose
    sort comparisons hash both sides, plus a number's formatting cost again, since RawEquals
    formats non-integers;
  - where the operands' types match down to a set, each set is sorted again by Equals, and
    every element pays its comparison weight for hashing. Comparing two elements is a full
    Equals of them. For compound elements that is the element's own marks walk: compound
    elements around colliding numbers share a hash, and a set of 40 lists nested 100 deep took
    4.8 s (T-0116b review). So each hash bucket with n1 and n2 elements whose comparisons cost
    m1 and m2 in total costs n1 × m2 + n2 × m1. When the elements hold sets, a bucket costs
    m1 × m2, except a bucket with one element on each side. Distinct elements hash apart, so
    that is the common case, and it costs two comparisons, 2 × (m1 + m2), plus comparing the sets
    inside the pair (T-0116b review: m1 × m2 refused 200 objects holding small sets, 86 ms of
    work).
- The acceptance suggested setComparisonWork, the product of the operands' sizes that
  contains and index use. It is rejected: comparing two large sets of distinct values is
  linear, and a product would refuse it.
- A timing sweep measured at most about 95 ns per unit for accepted values. It covered sets of
  strings, numbers and small objects (100 to 4,000 elements), colliding numbers, 512-bit
  fractions, lists and maps 25 to 50 deep around 20,000 strings, and colliding lists 20 deep.
  Lists of many tiny sets are overcharged about 5 times (follow-up T-0116e).
- Over the limit, the right operand becomes a dynamic unknown, the measured work is spent,
  m.cmpLimited makes the whole expression unknown, and evalExpr warns "Comparison too large"
  (expression_too_complex).

## Consequences
- Comparisons of primitive values cost nothing more, and shallow structures cost about their
  size. Deep values (a few hundred levels) are refused at sizes cty takes seconds over.
- Sorting sets on iteration is a cost every set walk pays, not only comparisons. Compound sets
  are the worst case, since they hash on every sort comparison. T-0116d charges the other walks,
  this estimator's own among them: it iterates the sets it charges before it can refuse.
