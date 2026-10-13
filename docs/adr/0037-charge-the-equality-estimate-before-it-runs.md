# 0037 · Charge the equality estimate's own walks before it runs

- Status: accepted
- Date: 2026-10-13
- Task: T-0116f
- Extends: ADR 0035, ADR 0036

## Context
ADR 0035 charges `==` and `!=` with equalityCost, which follows cty's work. To count that work,
equalityCost walks both operands itself. marksWalk iterates every set to count its sort, and
the set lookups iterate and hash every element of each compared set again. Iterating a set
sorts it every time (ADR 0036), so the estimate costs about as much as the walks it counts, and
it pays all of that before it can refuse. The operands were measured with valueSize, which
charges no sorts and so can't refuse a set that is too costly to sort. In the T-0116b review,
estimating and comparing 30 sets of 500 strings took 4.6 s, 12 × 12 × 48 sets nested three
deep 16.4 s, and 100 numbers with 8,192 fractional bits 3.3 s.

## Decision
- The comparison (operandsEqualityCost) measures each operand with valueSizeWalk, within the
  work left. A set too costly to sort is refused before it is iterated, and every operand is
  charged its size plus the sorts of its sets.
- Before equalityCost runs, each operand is charged equalityEstimateWork as well:
  equalityEstimateWalks (2) × (size + sort), for the estimate's own walks of it. A timing sweep
  measured the estimate at 2 to 2.6 times the measuring walk per operand, about 42 to 74 ns per
  unit of this charge. It covered sets of 2 to 20 sets of 200 strings, lists of such sets,
  4,000 seven-string tuples, 8,000 strings and 2,048-bit fractions. Sets nested deeper cost
  more, because the lookups hash and walk the inner sets again at every level they recurse
  into. The review measured 3.0 to 3.4 times the walk for sets nested two and three deep, and
  4.3 times for five deep. That is still 42 to 154 ns per charged unit, within the project's
  band, so the constant stays at 2 rather than refusing more shallow values.
- If the measurements and the estimate's walks pass the work left, the comparison is refused
  without running equalityCost. Otherwise equalityCost's result is added as before. Any refusal
  spends the work left, as before (ADR 0035).

## Consequences
- A refused comparison walks each operand at most once. Refusing a set of 20 sets of 200
  strings takes about one walk of it (about 0.3 s). Before, it took that walk plus about
  two more for the estimate.
- Comparisons now cost about three walks of each operand beyond cty's own work, so values near
  the limit are refused sooner. For example, a set of 10 sets of 200 strings is now refused,
  where cty's comparison took 0.6 s and the estimate 0.4 s.
- The first walk of a set of sets, or of a set of high-precision numbers, still sorts it before
  any walk can count it (T-0116i, T-0124). In a module the locals estimate makes that walk
  before the comparison, so whole-module times for the review cases are unchanged. They are
  bounded by those tasks and by T-0116g, which charges the remaining uncharged marks walks.
