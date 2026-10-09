# 0012 · Expand module calls by count and for_each

- Status: accepted
- Date: 2026-10-09
- Task: T-0107c
- Extends: ADR 0011

## Context
A module call with `count` or `for_each` loads one module instance per index or key. Each
instance has its own inputs (with `count.index` or `each.*`), resources and outputs, and the
caller sees `module.<name>` as a tuple or an object of them. Nested calls multiply: two levels
of `count = 200` are 40,000 instances. The tree budgets of ADR 0009 bound the work of evaluated
instances, but every instance, even a skipped one, holds its own state and list entry.

## Decision
- A call's count and for_each are evaluated in the caller, with the locals and module values
  available at the call's place in the dependency order (ADR 0011), and expanded as for
  resources (T-0106b):
  - at most 10,000 instances per call;
  - keys sorted;
  - an unknown or invalid expansion is one `[*]` placeholder with unknown `count.index` and
    `each.*`, and an unknown_expansion or invalid_expansion warning.
- Instance addresses follow Terraform: `module.a[0].module.b["k"]`. Resources inside take that
  address as their prefix and Module.
- The caller sees `module.<name>` as a tuple of output objects (count), an object of them by
  key (for_each), or one object without either. It is unknown for a placeholder or a cut
  expansion: never a partial tuple or object.
- Each instance after a call's first evaluates the call's arguments again. Their source bytes
  (times jsonEvalFactor for JSON) are charged to the caller's call expansion work, at most
  maxExpansionWork (2^21 bytes, about a second), as a resource body is. This counts toward the
  tree's expansion budget (ADR 0009). Past it, the call's expansion stops with an
  expansion_limit warning, and the caller sees it as unknown. (T-0107c review: a 250 KB
  argument took 124 ms per instance, so `count = 10000` would have taken about 20 minutes.)
- A tree has at most 10,000 module instances (the root not counted). Before each instance
  starts, a full tree stops the call's expansion with an expansion_limit warning at the call.

## Alternatives considered
- Expose the instances evaluated before a limit as a partial tuple: `length(module.x)` and index
  lookups would be silently wrong.
- Count instances only through the tree budgets: skipped instances cost nothing to the budgets
  but still take memory, so 40,000 or more could be listed.

## Consequences
- Positive: count and for_each modules are checked per instance, as Terraform plans them.
  Nested multiplication stops at 10,000 instances (tested at one level, at two nested levels,
  and at and just over the limit). Repeated argument evaluation stops at one module's expansion
  budget per caller.
- Negative / accepted risks: very large expansions are partly unchecked, visibly
  (expansion_limit maps to a limit_exceeded gap in T-0109).
