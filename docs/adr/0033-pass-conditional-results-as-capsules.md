# 0033 · Pass conditional results to their wrappers as capsules

- Status: accepted
- Date: 2026-10-10
- Task: T-0114i
- Extends: ADR 0026, ADR 0027, ADR 0030

## Context
ADR 0030 wraps each result of a conditional in an internal function. That made every
conditional count as a call for ADR 0026 and ADR 0027, which charge argumentWalkWork (4) units
per unit of the values an expression uses. `var.enabled ? local.cidrs : null` over 3,000
elements was charged about 144k units per evaluation, so about 58 resource instances used up a
module's function work. Plain hcl walks nothing here.

The walk is real, though. Before a call, cty walks each argument for marks with
`cty.Value.ContainsMarked`, over cty.DeepValues, whatever the parameter allows. It stops at the
first marked value, so only unmarked values pay in full. The cost depends on shape, not on
valueSize:
- about 10 ns per unit for a list of strings;
- 110 to 185 ns for scalars, empty objects and nested lists;
- about 1,300 ns for a set, which cty sorts to iterate (T-0114i review).

Every enclosing conditional walks the taken result again. A first fix charged a per-byte rate
once per expression, and was 10 to 100 times too low: a set of 20,000 numbers in 100 instances
took 22 s, and 100 nested conditionals in 300 instances took 51 s.

Taking the results as expression closures would break hcl's diagnostics for the result not
taken (ADR 0028).

## Decision
- The wrappers' result parameter has a capsule type (condResultType). Its customdecode expression
  decoder evaluates the argument itself, eagerly and as hcl would (`expr.Value(ctx)`), and
  returns the value in a capsule with the diagnostics. hcl evaluates a call's arguments in
  order, appends a decoder's diagnostics exactly as for an ordinary argument, and skips the call
  when they hold errors, so hcl's semantics are unchanged. cty walks only the capsule, and the
  wrapper returns the value inside it unchanged, with its marks and refinements.
- The wrappers then walk nothing in cty, so walksArguments does not count them (with
  `__iace_cond_begin`). An expression that calls nothing else is not charged an input walk.
- The unification and conversion charges of ADR 0030 to ADR 0032 are unchanged.

## Consequences
- Positive:
  - A conditional costs nothing beyond what hcl does, plus the unification it charges.
    `var.c ? local.cidrs : null` over 3,000 elements costs 0 units instead of 144k.
  - Costly shapes and deep nesting no longer have a walk to pay for. 300 instances over a set of
    20,000 numbers, or over 100 nested conditionals, finish in well under a second. With results
    passed as themselves they took 71 s and 15 s (mutation check).
- Negative / accepted risks:
  - The design relies on hcl's custom expression decoders (ext/customdecode) and on cty not
    walking into capsules. TestConditionalsMatchHCL and TestConditionalsOverCostlyShapesAreFast
    would catch a change.
