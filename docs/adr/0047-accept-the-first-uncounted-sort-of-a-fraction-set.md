# 0047 · Accept the first uncounted sort of a set of fractions

- Status: accepted
- Date: 2026-10-17
- Task: T-0124e
- Owner decision: D-T-0124e, option (b) (2026-10-17)

## Context
The evaluator charges work before it runs (ADRs 0008–0044). One cost cannot be seen in advance:
cty sorts a set before any accessor returns its elements (Values, ElementIterator, EachValue all
sort first), and it sorts again on every iteration. valueMarksWalk prices a set's sort from its
type, as if a set(number) held integers. A set of numbers with many fractional bits costs more to
compare, and its first sort happens before any walk can count it: one walk of 8,000 512-bit
fractions took 2.5 s, and 2,000 `N.1` decimals walked by 3 or 32 locals took 1.04 s and 1.11 s
(probes on main @ 398c595). The owner chose between three options (BACKLOG D-T-0124e):
(a) price every set element as a 512-bit fraction, (b) accept the uncounted first sort and record
it, (c) bound fractional bits where numbers are made.

## Decision
Option (b). Set sorts stay priced as integers, and this residual is accepted: **one uncounted
sort per set value that a module evaluation measures**, about 1 s for 2,000 512-bit fractions.
- cty keeps no sorted order: every walk of a set sorts it in full again (go-cty's set Values runs
  a full stable sort on every call). What bounds the cost is that each set value is measured once
  and the result cached: the measurement of `var.s` is walked once, spends its integer-priced sort
  from the module's function work (8.4M units), and when it passes the work left the cached "too
  large" result refuses every later local that takes the set ("Local value too large") without
  walking it again. Removing that cache would bring the repeats back.
- Module call instances do not repeat it. Every instance of a call evaluates its arguments with
  the caller's same variables and locals, so the measurement of `var.*` and `local.*` is shared
  across a caller's call decoders, and the walks of argument values spend their sorts from the
  caller's function work. Before this, each instance re-measured the value: a 2,000-fraction set
  passed to `count = 64` instances took 62 s, uncounted (T-0124e review). Module outputs are not
  shared, since a call evaluated later can change them.
- It is bounded by the conversion refusals: a set(number) of 4,000 `N.1` decimals, or 20 or more
  multiples of 1e-2466, is refused when the variable converts ("Variable value too large to
  convert").
- Regression tests: TestFirstSortOfAFractionSetIsBounded (2,000 `N.1` decimals in a set(number)
  default taken by 32 locals: the variable converts, all 32 locals are refused, about 1.1 s,
  bounded at 5 s scaled for the race detector), TestFractionSetPassedToModuleInstancesIsBounded
  (the same set passed to `count = 32` module instances: about 1.1 s instead of 31 s, same bound)
  and TestIntegerSetWalksAreAccepted (a set of 4,000 integers converts and is walked until the
  module's function work stops it).

## Alternatives considered
- (a) Price every element as a 512-bit fraction: it closes the residual but refuses realistic
  integer sets up front (4,000 integers would be priced about 15M units against the 8.4M
  per-module function work).
- (c) Bound fractional bits where numbers are made (literals, conversions, arithmetic): wider
  than one task, and it shares (a)'s integer-set trade-off at a smaller price.
- Charging the walks alone, without sharing the measurement across instances: each repeated walk
  is charged at its integer price (about 150,000 units for 2,000 numbers), so 32 instances stay
  well inside the budget while each pays about 1 s; the repeat must be avoided, not only charged.

## Consequences
- Positive: integer sets of realistic size stay usable; the residual is measured, bounded per set
  value and module evaluation, and guarded by tests that fail if it repeats.
- Negative / accepted risks: the evaluator's time bound holds only approximately for sets of
  fractions: about one uncounted sort (about 1 s for 2,000 512-bit fractions) per distinct set
  value a module evaluation measures, by design.
- The owner's premise does not reproduce. The task said 32 walks of a set(number) of 4,000
  integers are accepted (653 ms, probe on main @ 398c595). On main @ abfdd4f, locals that take
  the whole set stop at 20 of 32, `length(var.s)` at 2 and for-expressions at 7. The cause is the
  per-walk set-sort charge this decision keeps: each accepted walk spends its integer-priced
  sort, and once the work left falls below the set's sort estimate the walk refuses. The test
  guards what the decision relies on instead: the integer set converts, and at least 20 locals
  accept it (under option (a) the conversion itself would be refused).
- The set-sort tests run in `make test`'s step without the race detector (NONRACE_TESTS), like
  the formatting timing tests of ADR 0044: they time single-threaded math/big sorts, which the
  race detector slows several times, and together they added about 80 s under -race, enough to
  push internal/terraform past go test's 10-minute timeout on CI.
- Follow-ups: the harness copy of the threat model names the residual (T-0110b); the project's
  threat model (docs/security/threat-model.md, T3) names it in this change.
