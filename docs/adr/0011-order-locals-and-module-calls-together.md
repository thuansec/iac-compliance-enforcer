# 0011 · Order locals and module calls in one dependency graph

- Status: accepted
- Date: 2026-10-09
- Task: T-0107i
- Extends: ADR 0010

## Context
In Terraform, locals and module calls depend on each other freely: a local can use
`module.a.out`, and a call's arguments can use locals and other calls' outputs. ADR 0010
evaluated all of a module's locals before its calls, so those references were unknown, and a
policy could not see a value that came through a module. Ordering locals and calls together
moves locals after calls. That brings back the problem of ADR 0010 for locals: an ancestor
could evaluate locals at its full per-module budget after its subtree had used up the tree
budget.

## Decision
- A module's locals and calls form one graph: a local is its name, a call is `module.<name>`,
  and the edges are the references in each local's expression and each call's arguments.
  Strongly connected components (Tarjan, explicit stack) are evaluated dependencies first. A
  call is evaluated, its whole subtree included, when its turn comes, with the locals and
  module values evaluated so far.
- A cycle is reported and its members are unknown. Locals give local_cycle, as before, and calls
  give module_cycle. A call in a cycle is still evaluated, with the cycle's values unknown, so
  its resources are checked, but all its outputs are unknown to the module.
- Locals, module inputs, resources and outputs see `module.<name>` only for the module's own
  calls. Another name is an unsupported attribute: an evaluation warning, and the value is
  unknown.
- A child instance asks the tree budget before each local, with what it has used so far
  charged. Once a budget is used up, its remaining locals are unknown, and the instance is then
  truncated with a module_work_limit warning (ADR 0010). The root is always evaluated in full.

## Alternatives considered
- Evaluate locals in two passes, before and after the calls: a local that depends on a call
  whose arguments depend on that local would still need the graph, and the work would double.
- Exempt locals from the budget check: a chain of 30 modules whose locals depend on their call
  used 232M units of function work against an 8.4M budget (regression test).

## Consequences
- Positive: values flow through module outputs into locals and other modules' inputs in any
  declaration order, as in Terraform. The tree bound of ADR 0009 and ADR 0010 holds for locals.
- Negative / accepted risks: near the budget, an instance's later locals are unknown, visibly
  (the truncation warning). Terraform rejects cycles; iace keeps going with unknown values and
  warnings.
