# 0031 · Count types in value sizes

- Status: accepted
- Date: 2026-10-10
- Task: T-0114f
- Extends: ADR 0029, ADR 0030

## Context
Every evaluated value is measured by valueSize: one unit per value, plus string bytes, keys,
attribute names and number digits. An unknown value counted one unit whatever its type.

Unknown values can carry types far larger than any value. With `var.c` unknown, the chain
`u_k = var.c ? [local.u_{k-1}, local.u_{k-1}] : [local.u_{k-1}, local.u_{k-1}]` yields small
unknown values whose type doubles per local. cty walks types when it unifies and compares them:
22 locals took 14 s (T-0114c review). After ADR 0030, the charge for unifying equal types
stopped at its walk limit, but 20 locals still took 3.5 s, charged almost nothing.

The profile showed convert.unifyTupleTypes calling Type.Equals on the unified type at every
level, so a node is walked once per level above it: about 2.5 µs per node of a doubled type.

## Decision
- typeSize counts a type expanded, so a type used in several places counts each time. It stops
  past a limit, and a type nested deeper than the nesting limit counts as over it, as a known
  value would.
- valueSize counts an unknown or null value as its type's size, and adds the element type's size
  for an empty collection. A known value's other types are implied by its elements, which are
  measured. So every limit that measures values also bounds types: local values (2^18 units),
  resource attributes, function arguments and results, for-expression collections and module
  inputs. A value whose type passes the limit fails the check exactly as an oversized value does.
- In the doubling chain, the first check to refuse a local is the locals reference estimate
  (ADR 0025): it charges each reference with the size recorded for the local it reads, and those
  sizes now include types. u16 reads u15 four times, about 393k units, so it is refused before
  evaluation with `value_too_large`. valueSize is the backstop for types built within one
  expression: function and for-expression results, resource attributes, and a local's value after
  evaluation.
- ADR 0029's unifyWalk weights the types it walks by their nesting depth, for cty's Equals at
  every level.
- unifyTypesCost (conditionals and `coalesce`) charges that walk even when nothing is sorted:
  unifying two equal types still walks them. ADR 0030's "equal types cost nothing" now means no
  sort cost, but a linear walk. A conditional whose results have the same primitive type is not
  charged: there is nothing to unify or convert, and charging would refuse `var.c ? "a" : "b"`
  once a module's function work is spent. Different primitive types are still charged, for
  converting a number to a string, say.

## Consequences
- Positive:
  - The doubling chain is refused in about 0.1 s (it took 3.5 to 14 s). Deep chains of 3,000
    locals, each one level deeper, no longer take 65 to 95 s. Conditionals over the largest types
    allowed reach the function work limit instead of spending seconds.
- Negative / accepted risks:
  - Unknown values of collection or structural types now measure their type, a few units more
    than before. Budgets for large unknown objects, such as resource attributes, fill slightly
    sooner.
  - Weighting by depth over-charges where cty compares shared type values quickly: about 36 ns
    per charged unit for equal types reached through the same local, against about 100 ns
    budgeted.
  - Equal-type conditionals pay a walk proportional to their types (about 12k units for two
    3,000-element tuples), besides the input walks (T-0114i).
