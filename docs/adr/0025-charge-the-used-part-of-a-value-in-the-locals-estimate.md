# 0025 · Charge the used part of a value in the locals estimate

- Status: accepted
- Date: 2026-10-09
- Task: T-0114
- Extends: ADR 0020 (measurements are charged to the module's function work)

## Context
Before a local is evaluated, its size is estimated from above: its source plus every use of a
local, variable or module output at that value's full size. Six reads of one field of a 45 KB map
(`local.cfg.env`) were therefore estimated at 270 KB, over the 2^18 limit for one local, and the
local was refused as too large although its value was a few bytes (T-0104c review).

## Decision
- A use whose traversal has static steps after the name (attribute steps and literal indexes,
  legacy `.0` included) is charged the size of the sub-value those steps reach. The steps are
  resolved against the evaluated value with hcl's conversions (staticSteps).
  - hcl's Variables() ends a traversal at its first dynamic step (an index by an expression, a
    splat), so those uses are still charged the whole value. So is any step that does not
    resolve, and a path into a local that is not evaluated yet. The estimate stays an upper
    bound.
- Each path's size is cached by its text, and measuring it is charged to the module's function
  work, as ADR 0020 charges every measurement.
  - Different texts can reach the same data (`l["0"]`, `l["00"]`, nested attributes), so the cache
    alone would not bound the walking (3,000 aliased paths into a 120,000-element list took 80 s).
  - Each measurement stops at the work left. With no work left, the whole value's size is
    charged, which is measured once per name, and nothing is walked.

## Consequences
- Positive: locals that read a few fields of a large map are evaluated.
- Negative / accepted risks: path measurements share the module's function work with function
  calls, for expressions and lookup. A configuration with many paths into large sub-values can
  leave less of that work for them, which shows as limit gaps (fail closed).
