# 0027 · Charge input walks wherever expressions are evaluated

- Status: accepted
- Date: 2026-10-10
- Task: T-0114b
- Extends: ADR 0026

## Context
ADR 0026 charges a local the walk of its inputs before cty walks them, because cty checks every
argument of a call or operator in full before iace can refuse it. The same walk happens in
every other expression iace evaluates, and three gaps remained:
- Resource attributes (once per count or for_each instance), count, for_each, outputs and module
  inputs were not charged. 300 resources, or one with count = 300, each `length(var.c.l)` over a
  120,000-element list took about 20 s (T-0114a review).
- A variable reached by an index (`var["c"]`, which hcl also evaluates though Terraform rejects
  it) or as a bare `var` was not counted at all, though every variable was in scope:
  `var["c"] != null` walked the whole list for free, in locals and resources alike (T-0114b
  review).
- ADR 0026 counted every for expression as walking, because its rewrite calls `__iace_for`. But
  the closure-taking internal functions walk nothing in cty and charge their own work (ADR 0020,
  ADR 0023). Counting them charged loops twice: the realistic fan-out rose from 41% to 57% of
  its tree's function work.

## Decision
- The resource decoder's evaluation of every expression (evalBounded: resource attributes per
  instance, count, for_each, dynamic-block for_each, outputs, module inputs) charges the size of
  the values the expression refers to times argumentWalkWork (4) before it is evaluated, when
  the expression walks its arguments. These are the sizes its estimate already counts: whole
  variables, locals, module values, dynamic-block iterators and instance values.
  - Over the limit, the value is unknown with a function_limit warning and nothing is walked.
  - Locals and these paths share one helper, chargeWalk.
- A variable reference resolves by `var.<name>` or by `var["<name>"]` with a known string key.
  A bare `var`, or an index that is not a known string, counts the whole var object. If any
  variable is sensitive, an unknown result is sensitive too.
- walksArguments does not count calls to `__iace_for`, its reference functions or
  `__iace_lookup`, but still looks for calls and operators inside their arguments.

## Consequences
- Positive: walking inputs is bounded everywhere iace evaluates an expression.
  - The tests cover 300 resources, count = 300, 300 outputs and a module called 300 times; at
    most about 18 evaluations over the 120,000-element list fit the module's function work.
  - The `var["c"]` and bare `var` forms are covered too.
- Negative / accepted risks: these paths charge whole referenced values, not the sub-values
  static steps reach (ADR 0025 does that for locals only). So an expression that calls a
  function on a field of a large variable is charged the whole variable, and can reach the limit
  sooner (fail closed).
