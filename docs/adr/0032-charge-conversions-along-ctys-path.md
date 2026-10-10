# 0032 · Charge conversions along cty's path

- Status: accepted
- Date: 2026-10-10
- Task: T-0114g
- Extends: ADR 0029, ADR 0031

## Context
ADR 0029 charged a conversion from the value alone: every tuple, object or map in it cost
unifying its element types, whatever the target. That over-counted wherever cty does not unify.
A tuple converted into `set(string)`, or an object into `map(string)`, converts element by
element in linear time, yet a `map(string)` or `set(string)` variable of about 11,000 entries was
unknown.

Reading cty's convert package gives the exact places it unifies:
- for a known value, the conversion functions in conversion_collection.go;
- for an unknown or null value, `dynamicReplace`, which computes the target type from the
  source type. It unifies a tuple's element types for any list or set target, and an object's
  attribute types for any map target, even when the target element type is known: an unknown
  40,000-element tuple took 10.8 s to convert into `set(string)`.

## Decision
- conversionCost walks the value and the target type together (unifyWalk.convert), as cty does:
  - Nothing is charged when the target is the dynamic type or the value already has the target
    type.
  - Tuple into list or set of `any`: its element types are unified to find the element type.
    Each element is converted to that type, which is unknown here, so each is charged as
    valuePart (ADR 0029's value-only estimate). For a list, the converted elements are unified
    again.
  - Tuple into list or set of a known type: each element is converted. For a list, the converted
    elements are unified: n copies of the element type, or, when that type holds `any`, the
    elements' own types, since each converted element then keeps its own type (T-0114g review:
    a `list(list(any))` default of 4,000 objects with distinct attributes took 11 s, while
    copies of `list(any)` cost almost nothing).
  - Object into map of `any`: its attribute types are unified, and unified again after
    converting unless they are all primitive. Object into map of a known type: each attribute is
    converted, then unified when the element type is a collection or an object (as above for a
    type holding `any`).
  - Map into map: each element is converted, then unified when the element type is a collection
    or an object.
  - Tuples, objects, lists and sets into their own kinds: element by element.
  - Unknown or null values: replace mirrors dynamicReplace and charges its unifications.
  - A target holding `any` (other than `any` itself, a passthrough) is also charged the
    type-level work, as in ADR 0029 (typeConversions): cty builds the conversion from the types
    before touching a value, unifying where a dynamic target leaves an element type open, even
    where no value reaches it (an empty list of tuples, a target attribute a map lacks: 4 s
    each, uncharged by the value walk; T-0114g review). This also covers the converted
    elements' own types above, which the value walk charges as a second layer.
- Optional-attribute defaults keep ADR 0029's charge (defaults).
- `tolist`, `toset` and `tomap` are charged their conversion into `list(any)`, `set(any)` and
  `map(any)`. `coalesce` and expanded `lookup` convert to a type known only during the call, so
  they keep the cautious estimate (conservativeCost: every tuple and object type unified, plus
  valuePart), with the arguments' types unified together.
- Conditionals keep valuePart for converting their results to the unified type (ADR 0030).

## Consequences
- Positive:
  - These now cost nothing and are evaluated: tuples into `set(string)`, objects into
    `map(string)`, lists of tuples into the same type, and lists into `list(string)`. Variables
    of that kind with tens of thousands of entries are known again.
  - Unknown and null values are charged where dynamicReplace unifies, a path the value-only
    estimate missed for known targets.
- Negative / accepted risks:
  - The estimate relies on reading cty v1's convert package. A cty upgrade must re-check
    convert, replace and the tests in TestConversionCostFollowsCty, which compare it with cty's
    timing.
  - The parts converted to a type known only during the call (elements of a tuple converted to
    a list of `any`, `coalesce`, conditional results) and targets holding `any` are still
    estimated conservatively, so they can over-count. Only conversions into fully known types
    are charged exactly.
