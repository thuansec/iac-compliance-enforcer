# 0036 · Charge the sorts of sets when values are measured

- Status: accepted
- Date: 2026-10-11
- Task: T-0116d
- Extends: ADR 0026, ADR 0035

## Context
cty sorts a set every time it is iterated, n × log2(n) comparisons. Each comparison walks both
elements for marks and, for compound elements, hashes both (setRules.Less, makeSetHashBytes);
numbers that are not integers compare by their exact decimal text. iace measures values by
walking them (valueSize), and the measurement was charged only the value's size. So a walk of a
set cost far more than its charge: six `length(var.s)` locals over a set of 8,000 seven-string
tuples took 14.4 s, and three for expressions over a set of 12,000 tuples 4.4 s (T-0114k review).
ADR 0035 already charges the sorts of equality operators (setSort), but only there.

## Decision
- valueSizeWalk measures a value as valueSize did and also returns the sort work of every set it
  walked: per set of n elements, log2(n) × (n × base + the size of its elements / divisor), plus,
  for a set of numbers, nonIntegerSortWork per element and level (20 plus numberFormatCost for a
  number that is not an integer). Compound elements cost a base of setSortWork (16) and their
  full size; primitive ones primitiveSortWork (2) and an eighth of their size. When the elements
  can hold sets, the sorts of the sets inside them count again nestedSortFactor (4) times per
  level, since each sort comparison hashes both elements, which sorts every set inside them. A
  timing sweep of sets of 1,000 to 8,000 strings, tuples, objects, integers, halves, thirds and
  512-bit fractions measured 67 to 154 ns per unit, and sets of 4 to 500 sets of strings 67 to
  99 ns per unit where accepted.
- Before it iterates a set, valueSizeWalk estimates the sort from the length and the element
  type, a lower bound of its charge, and refuses the value when the estimate passes the work the
  caller has left; it refuses too once the sort it counts passes that work. A refusal reports a
  size past the limit, so callers that read only the size treat the value as too large.
- Every measuring walk charges its sort, a refused one included (the walk it did, or the
  refusal's sort past the work left, so the next measurement is refused before it iterates), and
  every later walk of the value the sort again:
  - function arguments (measureArgs) are charged twice the sort, the measurement and cty's marks
    walk before the call, within half the work left; a refused measurement pays the sort it did;
  - the locals estimate charges each measurement's sort (variables, module values, paths and
    evaluated locals), and a walking local adds the sorts of the values it uses to the walk it
    charges, which argumentWalkWork multiplies, as each of cty's walks sorts again;
  - a for expression's collection is charged twice its sort (measured, then iterated by hcl),
    and the references its body walks each iteration their sort per iteration.

## Consequences
- Walks of large sets of tuples or objects stop at the module's work instead of repeating for
  free; ordinary sets (a thousand strings) cost a small part of it.
- Not covered here (T-0116f): the estimators' own walks (equalityCost, marksWalk, conversion
  estimates) and the marks walks iace makes without measuring (inputsSensitive).
- The first iteration of a set sorts it before any element is counted, and the up-front estimate
  sees only the element type: a set of 100 sets of 200 strings takes about 2.7 s to walk once
  (T-0116f), and a set of 8,000 numbers with 512 fractional bits about 2.5 s (T-0124). Later
  walks are refused.
