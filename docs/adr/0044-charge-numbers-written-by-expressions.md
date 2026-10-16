# 0044 · Charge numbers that templates, keys and format write as text

- Status: accepted
- Date: 2026-10-14
- Task: T-0124b
- Extends: ADR 0043, ADR 0033

## Context
ADR 0043 charges numbers that cty's conversions make strings. hcl also writes numbers as text
itself, outside iace's function table:
- template parts beside literal text (`"x${n}"`);
- for expression keys and object constructor keys;
- an index into a map;
- format and formatlist, through cty's stdlib.

Writing costs numberTextCost: about the square of the number's precision and fractional bits.
An object for expression over 90 multiples of 1e-2466 took 198 ms but was charged 8,377 units.
1,000 templates over a number at 8,192 bits took 2.4 s, and `format("%v", 1e-300)` took 100 µs
per call, with nothing charged for the text.

## Decision
- After parsing, rewriteForExprs passes each such part through `__iace_text(S, part)`, once:
  - template parts beside literal text;
  - for expression keys;
  - object keys that are not bare names;
  - IndexExpr keys.
  The wrapper takes the part in a capsule, as the conditional wrappers do (ADR 0033), so cty
  walks nothing of it. It charges numberTextCost and returns the part unchanged. S is a capsule
  no configuration can write. Over the limit the part becomes a dynamic unknown with its marks,
  the work is spent, and evalExpr returns the whole value unknown with "Number formatting too
  large". A template that is a single interpolation is the value itself, so it is not wrapped.
- Literals are never wrapped. Wrapping would hide them from code that reads them statically:
  quoted keys in required_providers, and optional() defaults with numeric keys such as
  `{ 80 = "http" }` (T-0124b review). Instead, literalTextCost prices the literal numbers in
  those positions, and the index steps of traversals, from the source. hcl parses
  `local.m[1e-2466]` as a traversal, which cannot be wrapped.
  - A literal whose numberTextCost passes maxSetNumberFormatCost (1,089 units, a fraction with
    1,024 fractional bits) makes the expression unsafe to evaluate: it is unknown with
    "Expression too complex". This applies in .tf.json templates too (jsonTemplateCalls). The
    review measured nested loops over `var.m[1e-2466]` in .tf.json at 25 s.
  - For expressions add the literal cost of their body to every iteration's charge (nested
    ones count again, an over-count). The review measured 100,000 uses of `var.m[1e-150]` at
    5.2 s and of `var.m[7]` at 1.7 s, both uncharged.
  - chargeDefault adds it to the two evaluations of an optional() default.
  - evalExpr charges an expression's total literal cost on every evaluation, refusing it with
    "Number formatting too large" when it does not fit, and spending the work. The re-review
    measured one local holding 10,000 uses of `local.m[1e-150]` (1,024 units each) at 1.6 s
    uncharged, and a module holding it at 75 s under count = 60. A 512-bit integer costs 121.
  - Literal index keys into lists and tuples are charged too, though hcl makes them numbers,
    not text. This is an accepted over-count: 122 units per `x[0]`, about 15% of a module's
    function work over 10,000 iterations.
- format and formatlist charge numbersTextCost of their arguments as call work. For formatlist
  that is every list element, plus every scalar once per row.
- ADR 0043's precision term is recalibrated from (Prec / 32 + 1)² to (Prec / 48 + 1)²
  (precisionBitsPerUnitRoot). With the templates charged, the realistic fanout tree used 59% of
  the tree's function work: 100 templates per instance each write a 512-bit port number, 14 µs
  apiece. At root 48 a 512-bit integer costs 121 units, 114 ns per unit, the least that stays
  within the 120 ns calibration, and the fanout tree uses 49.3%. A sweep of conversions at 512,
  2,048 and 8,192 bits measured 40 to 111 ns per unit.

- The three tests that time math/big formatting run in make test's non-race step
  (NONRACE_TESTS, formerly HEAP_TESTS, with -v so their durations show in CI). Under -race that
  formatting runs about 25 times slower, past raceSlowdown: the three took about 190 s and
  pushed internal/terraform past go test's 10-minute timeout.

## Consequences
- 1,000 templates or format calls over an 8,192-bit number, and a sensitive one, stop at the
  module's work in under 1 s each, and the refused values keep their marks.
- The ADR 0043 regression module now stops at the tree budget in 3.2 to 3.7 s over five local
  runs, and 3.62 to 3.72 s on CI (2 s with root 32): the budget at about 100 ns per unit. The
  review saw one 4.32 s run under load. A tree charged accurately to its budget takes about the
  budget at the 120 ns calibration, 4 s, so the owner chose (2026-10-14) to keep root 48 and
  raise that test's bound from 4 s to 5 s. The alternatives were root 40–44 with realistic trees
  allowed about 55% of the tree's work, or a larger tree budget.
- Left for T-0124c: number-to-string mixes found only after unifying, and sets of numbers with
  many fractional bits sorted before any walk can count them.
