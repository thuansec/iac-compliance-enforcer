# 0009 · Bound the evaluation work of a module tree

- Status: accepted
- Date: 2026-10-09
- Task: T-0107g
- Extends: ADR 0008
- Amended by: ADR 0021 (the tree's function work is four modules' worth), ADR 0022 (and its
  expansion work)

## Context
Each module instance is evaluated within per-module budgets: function work (2^23), locals and
resource values (2^22 units each), re-evaluated source for expansion (2^21 bytes), instance
structure (2^27 estimated bytes) and instances (100,000). ADR 0008 lets a tree hold up to 1,000
module calls, and each resolved call is an instance that also re-evaluates its module's
source (variable defaults, locals, resources). Without a tree-wide bound, 1,000 instances
multiply every per-module budget: a fan-out to a module that reads 200 KB of source and spends
its function budget would take minutes and hold gigabytes. The inputs of one caller's calls also
had a fresh value budget per call.

## Decision
- The tree has a budget for each kind of work and memory, each charged on its own:
  - 8 MiB of child-instance source. The root is always evaluated and is not charged, so a large
    root never skips its children.
  - one module's budget of each of: function work, locals values, resource values, module input
    values, local reference entries, expansion work, instance structure and resource instances.
  - 2^20 steps of unknown paths (locals and resources). These hold about 128 bytes per path,
    which their value units do not count.
- An instance is evaluated only while every tree budget has some left, and charged after
  (EvaluateTree). For each kind, the tree therefore uses at most its budget plus one instance's
  use of that kind: at most two modules' worth of any per-module budget.
- A caller is charged again after evaluating each call's inputs, and the inputs of all of one
  caller's calls share one value budget (maxResourcesSize).
- An instance past the budget is Skipped, with a module_work_limit warning at its call. Its own
  calls are not listed. T-0109 maps the warning to a limit_exceeded gap.

## Alternatives considered
- Divide the per-module budgets among instances in advance: the tree size is not known up
  front, and one large module would starve the many small ones.
- Keep per-module budgets only: a hang or OOM within the call limit.
- Lower MaxModuleCalls instead: legitimate trees of many small modules would lose coverage,
  while a few large modules would still multiply the budgets.

## Consequences
- Positive: 1,000 small instances evaluate in full (tested). Each kind of work or memory is
  bounded at two modules' worth: the function fan-out test stops after 2 instances, and the
  source fan-out test after about 42. The reviewer's probes (chained locals at 51.7M reference
  entries, and unknown paths at 2.3 GiB live) are regression tests.
- Negative / accepted risks:
  - A large tree of large modules is partly unchecked, visibly, and fails with `--fail-on-gaps`.
  - One module's unknown paths are not bounded by the per-module budgets: 3M paths took
    385 MiB in one module (T-0118). The tree bound adds at most one such module beyond 2^20
    steps.
  - Values can weigh more memory than their units (T-0118).
- Follow-ups: T-0109 (gap mapping); T-0118 (memory weight of values and unknown paths).
