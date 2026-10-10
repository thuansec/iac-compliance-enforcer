# 0026 · Charge the inputs of locals that call functions

- Status: accepted
- Date: 2026-10-10
- Task: T-0114a
- Extends: ADR 0020, ADR 0025
- Extended by: ADR 0027 (resources, outputs and module inputs; var index forms; internal functions)

## Context
cty runs function calls and operators (`length(x)`, `x != null`, `a + b`) as functions, and
before any of iace's wrappers run, cty walks every argument in full to check it for marks, and
often unmarks it and checks that it is known. A call that iace then refuses for its size has
already walked its arguments. So many locals that each call or compare one large input walk it
once per local, for free: 3,000 locals `length(var.c.l)` over a 120,000-element list took about
140 s, and 1,000 locals `var.c.l != null` about 44 s (T-0114 review). Only an argument passed as
an expression closure avoids the walk (ADR 0023), and rewriting every function and operator that
way would be a large change.

## Decision
- A local whose expression calls a function or applies an operator (walksArguments: a for
  expression counts, as its rewrite calls `__iace_for`; a .tf.json expression is assumed to) is charged, before it is evaluated, the part of its size estimate
  that its inputs make up (ADR 0025: the size of every value or sub-value it uses, without its
  own source) times argumentWalkWork (4) to the module's function work. The walks cost about 400 ns per unit of input in all, against about
  100 ns per unit of function work.
- If the module cannot pay for it, the local is unknown with a function_limit warning, and
  nothing is walked.
- A local that only refers to values, with no call or operator, is not charged for walking:
  nothing walks its inputs.

## Consequences
- Positive: walking inputs across all locals is bounded by the module's function work.
  - 3,000 locals over the 120,000-element list take about 1 to 2 s, the same as 300.
  - About 17 of them are evaluated before the limit; the rest are unknown with a warning.
- Negative / accepted risks:
  - Locals that call functions on large inputs draw on the same function work as the calls
    themselves, so some such locals are charged twice and the limit comes sooner.
  - Resource attributes, count and for_each instances, outputs and module inputs are not charged
    this way yet, and the same walk happens there before any budget: 300 resources, or one with
    count = 300, each computing `length(var.c.l)` over 120,000 elements take about 20 s
    (T-0114b).
