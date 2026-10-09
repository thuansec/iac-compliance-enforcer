# 0010 · Evaluate module calls before resources and outputs

- Status: accepted
- Date: 2026-10-09
- Task: T-0107h
- Extends: ADR 0009

## Context
A caller's resources and outputs reference its module calls' outputs (`module.net.id`), so an
instance now evaluates its calls before its own resources and outputs: variables, locals,
calls (recursively), then resources and outputs. ADR 0009 checks the tree budgets only before an
instance starts. With the calls in the middle, every ancestor still on the call stack (up to 32)
would decode its resources and outputs after its descendants had used up the tree budget. The
T-0107h review measured a chain of 30 resource-heavy modules at 29 times the budget. Outputs
are also a new kind of value to budget.

## Decision
- An instance evaluates its variables, locals and calls, then its resources and outputs, which
  see each call as `module.<name>`: an object of its outputs, or unknown when the call is
  unresolved, skipped or truncated.
- After its calls return, a child instance checks the tree budgets again. If any is used up,
  the instance is Truncated: its resources and outputs are not evaluated (its outputs are
  unknown to its caller), with a module_work_limit warning at its call. The root is always
  evaluated in full.
- Output values have a tree budget of one module's maxResourcesSize, like module inputs, and
  their unknown path steps count toward the 2^20-step budget of ADR 0009.

## Alternatives considered
- Cap each instance's remaining budgets by what the tree has left: more coverage near the limit,
  but every per-module budget (values, function work, expansion, structure, instances) would
  need a tree-aware limit.
- Evaluate resources before calls: callers' resources could never see module outputs.

## Consequences
- Positive: each kind stays within the tree budget, plus one instance's use, plus the root's.
  The deep-chain probe is a regression test.
- Negative / accepted risks: when a deep subtree uses up the budget, the resources of every
  ancestor below the root on that path are unchecked. This is visible as warnings, and fails
  with `--fail-on-gaps`.
- Follow-ups: T-0107i (locals and module inputs see outputs); T-0109 maps module_work_limit for
  skipped and truncated instances.
