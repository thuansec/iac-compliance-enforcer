# 0030 · Charge conditionals with both results in hand

- Status: accepted
- Date: 2026-10-10
- Task: T-0114e
- Supersedes: ADR 0028's per-result charge (its rewrite and limit diagnostic stay)
- Extends: ADR 0029
- Extended by: ADR 0031 (equal types charged their walk)
- Extended by: ADR 0033 (results passed as capsules, not walked)

## Context
ADR 0028 wraps each result of a conditional and charges the unification of its type alone,
because a wrapper sees only one result. That was wrong both ways:
- It over-charged. hcl unifies only when neither result is a dynamic null nor of the dynamic
  type, and unifying two equal types costs nothing. Yet `var.enabled ? local.cidrs : null` over
  3,000 elements was charged about 560k units per evaluation, so about 15 resource instances
  used up a module's function work (T-0114c review).
- It under-charged. Nested tuples of different lengths are unified together only once both
  results are known: `true ? var.n : [["x"]]` over 36 tuples of about 1,000 elements took 8.5 s,
  charged nothing (T-0114d review).

hcl evaluates the true result, then the false result, then unifies their types (convert.UnifyUnsafe),
and finally converts the taken result to the unified type. Our own expression types cannot be put
into an hclsyntax tree, so the hook has to be a function call.

## Decision
- Every conditional in a syntax tree iace evaluates is rewritten (with ADR 0020's rewrites):
  `c ? a : b` becomes
  `c ? __iace_cond_true(__iace_cond_begin(S), a) : __iace_cond_false(S, b)`.
  S is a cty capsule holding the conditional's state. Only the rewrite can create it, since no
  configuration can write a capsule literal. A configuration that calls the functions itself
  therefore gets a type error, and cannot reach or forge another conditional's state. The
  rewrite recognises its own wrappers by S, so it stays idempotent.
- hcl evaluates a call's arguments in order, and the true result before the false. So
  `__iace_cond_begin` resets S before `a` is evaluated, `__iace_cond_true` records `a`'s value
  after it, and `__iace_cond_false` reads that record, clears it and decides. A true result that
  fails before its wrapper is called leaves no record, so a stale record from an earlier
  evaluation is never used.
- `__iace_cond_false` mirrors hcl's decision. If either result is a dynamic null or of the dynamic
  type, or no true result was recorded, nothing is charged. Otherwise the charge is ADR 0029's
  unifyWalk over the two types (equal types cost nothing). When the types differ, converting
  both values to the unified type (ADR 0029's value conversion cost) is added, whatever the
  unification cost: two map types unify cheaply through their element types, but converting a
  map of lists unifies all its entries (T-0114e review: 20,000 entries took 2.7 s). Only the
  taken result is converted, so this can over-count.
- Over the limit, the false result is a dynamic unknown that keeps its marks, so hcl does not
  unify. A true result taken would come back unconverted, since its wrapper had already returned
  it, so `evalExpr` makes the whole expression unknown (keeping its marks) and reports
  `expression_too_complex` ("Conditional too large"). This fails closed, as ADR 0028 did for the
  taken result.
- The wrappers take the results as ordinary arguments, so hcl's diagnostics, marks, unknowns and
  refinements are unchanged. cty walks each argument for marks, so a conditional still counts as
  walking its inputs (ADR 0026, ADR 0027).
- unifyCost, ADR 0028's per-result estimate, is removed.

## Consequences
- Positive:
  - `cond ? x : null`, `cond ? x : x` and conditionals with a dynamic result cost only the walks
    of their inputs. A module can now evaluate such conditionals over 3,000-element lists in
    every resource instance.
  - Nested tuples, mixed types and objects with different attributes are charged when, and only
    when, hcl unifies them. `true ? var.n : [["x"]]` stops at the limit in milliseconds.
  - Values and diagnostics are still hcl's (TestConditionalsMatchHCL adds nested conditionals,
    a failing true result with the false result taken, and conditionals in for expressions).
- Negative / accepted risks:
  - A refused conditional makes its whole expression unknown, even the parts outside the
    conditional (an object holding it, say).
  - cty walks each wrapper's argument for marks, which plain hcl does not do for results, so a
    conditional pays the walk of both results (about 144k units for a 3,000-element list) on
    every evaluation (T-0114i).
  - The conversion of both results is charged, although hcl converts only the taken one.
  - The rewrite depends on hcl evaluating the true result before the false one and arguments in
    order. TestConditionalRecordIsReset and the parity tests would catch a change.
