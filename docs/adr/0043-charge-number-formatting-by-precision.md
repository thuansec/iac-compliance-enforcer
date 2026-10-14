# 0043 · Charge converting numbers to strings by their precision

- Status: accepted
- Date: 2026-10-14
- Task: T-0124
- Extends: ADR 0029, ADR 0032

## Context
cty converts a number to a string with exact shortest decimal formatting
(`big.Float.Text('f', -1)`). That costs about the square of the number's precision, whatever its
value. HCL parses every literal at 512 bits, so `123` takes 14 µs, against 1.1 µs at 64 bits.
At 2,048 bits it takes 160 µs, and at 8,192 bits 2.4 ms. The conversion estimate charged a
number converted to a string one walked step, and setBuild charged the copy it converts to hash
only its digits. A child module with a `list(set(any))` default of 300 rows `[i, i + 1, "x"]`
under `count = 800` spent half its time in that formatting. It took 12.9 s in the T-0116 review
and 7.8 s on main before this change.

## Decision
- numberTextCost(v) = max((Prec / fracBitsPerUnitRoot + 1)², numberFormatCost(v)) +
  numberIntegerTextCost for a known, finite, non-zero number, and 0 for anything else.
  numberFormatCost covers numbers far below 1, whose fractional bits pass their precision.
  numberIntegerTextCost covers numbers far above 1: d + d² / 100,000 for the d digits of the
  integer part. At 512 bits 1e10000 took 0.8 ms, 1e100000 20 ms and 1e300000 109 ms, which
  this term prices at 35 to 100 ns per unit (T-0124 review: 1e100000 had been charged 289 units).
- It is charged wherever the conversion estimate sees a number become a string:
  - unifyWalk.convert, for a number converted to `string`;
  - toStrings, for the numbers in a tuple, object or map whose primitive element types unify to
    `string`, both at the top of a conversion to a collection of any and inside valuePart;
  - setBuild, again for the copy it converts to hash;
  - conversionWork, for a number passed to a `string` parameter.
- Timing sweep: tuples of 100 to 4,000 integers, fractions and mixed values at 512, 2,048 and
  8,192 bits, converted to list(string), set(string), list(any) and set(any). Every accepted
  case measured 18 to 80 ns per unit.

## Consequences
- The regression module stops at the tree budget in about 2 s (it took 7.8 s), and one instance
  still evaluates its default.
- Not charged yet (T-0124b): templates (`"${var.n}"`), format and formatlist (`Text('g', -1)`),
  numbers used as object or map keys (for-expression keys, `{(n) = ...}`, indexing a map by a
  number),
  mixes found only after unifying (such as tuple columns that unify to strings), and numbers of
  huge precision made by literals, conversions, arithmetic or parseint before any walk sees
  them.
