# 0038 · Take marks from the measuring walk

- Status: accepted
- Date: 2026-10-13
- Task: T-0116g
- Extends: ADR 0036

## Context
iace decides whether a value is sensitive with cty's ContainsMarked. That is a full walk of the
value (DeepValues), and it sorts every set it meets (ADR 0036). Nothing charged these walks:
- the locals estimate checks each local's inputs (inputsSensitive) and each evaluated local;
- a refused function call checks its arguments, so its unknown result keeps their marks;
- the resource decoder checks each variable, local and module value a reference reads, each
  count/each instance value and each dynamic block iterator.

Each of these values was measured just before, by a walk of the same value. For a set of 12,000
tuples, the check cost 0.8 s on top of the measurement. Three locals
`length(true ? var.t : toset([["a", …, "g"]]))` over such a set took 1.7 s, about two walks
(T-0114k review, after T-0116d).

## Decision
- valueMarksWalk is valueSizeWalk that also reports whether the value contains a marked value,
  with the same meaning as ContainsMarked. It unmarks every node it visits, so knowing the marks
  costs nothing extra. A walk that stops before the end (past its size limit, its depth or the
  work for its sorts) reports marked, since a mark may lie in the part it did not reach. That is
  fail closed: an input that could not be measured makes the result sensitive.
- Every measurement listed in the context now records the marks, and the sensitivity check
  reads them:
  - the locals estimate keeps the marks of "var", "var.<name>" and "module.<name>" from its
    measurement (size), which inputsSensitive now triggers when it runs first, and of each
    evaluated local from evalLocal's measurement;
  - measureArgs returns the arguments' marks, which a refused call's result takes;
  - the resource decoder's reference measurement, count/each instances and dynamic iterators do
    the same.
- ContainsMarked stays only where nothing was measured: unknown results of locals, and
  isSensitive's cache miss, which a reference never reaches because the reference measures first.

## Consequences
- The three locals above now take 0.84 s, about one walk of the set, and a check of sensitivity
  adds no walk.
- A value too large to measure now makes the values that use it sensitive, even with no mark in
  it. Such values are already refused (too large), so the change affects only unknown results.
- cty still walks a function's arguments for marks before the call (returnTypeForValues). When
  an argument is a set built by a conversion, that walk sorts it. Charging the sorts of sets
  that conversions build is T-0116h. With 12,000 tuples passed as a tuple, not a set, the three
  locals take 2.0 s (3.1 s before), and the rest is that walk.
