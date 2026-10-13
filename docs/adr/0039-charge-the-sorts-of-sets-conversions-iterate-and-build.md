# 0039 · Charge the sorts of sets that conversions iterate and build

- Status: accepted
- Date: 2026-10-13
- Task: T-0116h
- Extends: ADR 0029, ADR 0032, ADR 0036

## Context
cty sorts a set every time it iterates it (ADR 0036). The conversion estimate (unifyWalk:
conversionCost, condConversionCost and setBuild) is used by function arguments, conditionals,
lookup defaults and variable values. It iterated sets in several places: converting each
element, valuePart, defaults and setBuild. Each of those iterations sorted the set, and the
estimate charged none of them. cty's own conversion iterates a set it converts, sorting it once
more. When a conversion builds a set, whatever receives it iterates it at least once, starting
with cty's walk of a function's arguments for marks, which runs before anything can measure
them. Three locals `length(true ? var.t : toset([["a", …, "g"]]))` over a tuple of 12,000 tuples
of numbers took 2.1 s, half of it in those walks (T-0116g).

## Decision
- Every set the estimate iterates goes through unifyWalk.elements. It charges one sort per
  iteration with valueSizeWalk's model (elementSortWork): per element and level of the sort,
  setSortWork plus the element's size for compound elements, and primitiveSortWork plus an
  eighth of the size for primitives (plus the decimal comparisons of non-integers). The
  element's comparison weight stands in for its size.
- Before it iterates a set, elements charges the sort's lower bound (elementSortFloor per element
  and level: for compound elements setSortWork plus the size of their type, as valueSizeWalk's
  up-front estimate counts). When that alone passes the limit, the set is refused without being
  iterated. Once it has iterated, the sort is recorded as work done (unifyWalk.done), so a
  refused variable conversion spends it and cannot repeat it for free.
- Converting a set to a list or set charges that sort twice: once for the estimate's iteration
  and once for cty's.
- setBuild charges one sort of the set it builds: elementSortWork per distinct element, times
  the levels of the distinct count. Repeated values cost nothing more, since cty keeps one copy.
- The sort model of the equality estimate (setSort, ADR 0035) was not reused. A sweep of sets
  built from 1,000 to 5,000 tuples of 2 and 8 strings measured one iteration at 20 to 38 ns per
  unit of setSort, about four times over. valueSizeWalk's model measured 69 to 92 ns per unit.

## Consequences
- In the regression, the first local's conditional is charged the built set's sort and uses
  most of the module's work, and the other two are refused before converting. The three locals
  take about 1.0 s, against 2.1 s before. That is about 140 ns per charged unit, at the upper
  end of the calibration band.
- Converting a set too costly to sort is refused before the estimate iterates it. A set of
  40,000 seven-string tuples took 2.6 s to refuse before.
- Sets of sets are still iterated, and so sorted, before any walk can count the inner sets.
  The estimate's per-iteration sort also lacks valueSizeWalk's nested term for them. Both are
  left to T-0116i.
