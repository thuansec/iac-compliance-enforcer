# 0029 · Charge conversions into collection types

- Status: accepted
- Date: 2026-10-10
- Task: T-0114d
- Extends: ADR 0028
- Extended by: ADR 0030 (conditionals charged with unifyWalk)

## Context
ADR 0028 charges the unification of large tuples in conditionals. cty runs the same quadratic
sort (convert.sortTypes, every pair of element types compared) whenever it converts a value
into a collection type (profiled):
- a tuple converted to a list unifies its element types after converting them, whatever the
  target element type; with `any` as the target element type it also unifies the types first;
- a tuple converted to a set unifies only for `set(any)`;
- an object converted to a map unifies for `map(any)`, and after converting for a map of
  collections or objects; a map whose elements it converts to collections or objects does too.

At 10,000 elements a conversion took 0.6 s (1.3 s into `list(any)`), and four times as long for
each doubling: `tolist(var.t)` over 20,000 elements took 9.8 s per local, a `list(any)` variable
default as long 4.7 s, and a module input into `list(string)` 14 s at 40,000. Functions convert
in two places: hcl converts an argument to its parameter type (`join`, `sort`, `compact`,
`chunklist`, `zipmap` and the set functions take lists or sets), and some functions convert or
unify inside the call (`tolist`, `toset`, `tomap`, `coalesce` and `lookup`'s default, 1.3 to 2.5 s
at 10,000 elements). Variables convert their values to their type constraints, from defaults,
tfvars, `--var` flags and module inputs.

cty converts each value nested in another on its own, so a list of k large tuples converted to a
list of lists unifies k times. A cost read from the type alone would charge one.

## Decision
- An estimate of cty's unification (unifyWalk) follows its rules: unifying k types sorts them,
  every pair compared, costing k × k / 16 (about 6 ns per pair against about 100 ns per unit of
  function work); tuples of one length then unify column by column and tuples of different
  lengths all their element types together, objects likewise by attribute names, collections of
  one kind by their element types; a dynamic type among them ends it. Mixed types are sorted
  comparing compound types element by element and then tried in turn as the result, so each pair
  costs times the size of the largest type. There is no length
  threshold: tuples just within 1,024 elements, nested in one, sort together (T-0114d review: a
  tuple of 36 such tuples took 25 s in `tolist`).
- `conversionCost(value, target)` charges converting a value, in those units:
  - every known tuple, object or map value in it costs unifying its element types: cty converts
    each nested value on its own and unifies its elements after converting them;
  - when the target holds `any`, every tuple and object type in the value also costs unifying
    its element types, for the unification that picks the element type;
  - with `optional()` defaults, every list, set and map value costs k × k / 16 per attribute of
    the constraint's widest object, plus one: typeexpr unifies the elements it rebuilds;
  - the values and types walked are added once there is a cost. The walk stops at the work left.
- unifyCost (ADR 0028), the conditional charge, also charges object types with more than 1,024
  attributes: unifying objects with different attributes makes a map and sorts the attribute
  types. Conditionals keep ADR 0028's per-result estimate otherwise (T-0114e).
- Function calls: the bounded wrapper adds the conversion cost of every argument whose parameter
  type holds a list, set or map type, and of every argument of `coalesce`, `lookup` (when
  expanded, the only form not rewritten to `__iace_lookup`), `tolist`, `tomap` and `toset`,
  charged as if into `any`; for `coalesce`, also the arguments' types unified together. It is
  charged with the work checked before the arguments are converted, in the type pass and in the
  call, as both convert. Over the limit the call is unknown with `function_limit`, and a refusal
  in the type pass spends the estimate, so a call with an unknown argument (whose call cty
  skips) cannot repeat the walk for free. The conditional wrapper spends its estimate on refusal
  too.
- `lookup` (rewritten to `__iace_lookup`, ADR 0023) charges converting its default into a map's
  element type when that type holds a collection type, whether or not the default is used. Over
  the limit the result is unknown, with the marks of all arguments.
- Variables: before a known value gets its defaults and is converted to a type constraint that
  holds a collection type, the conversion cost is charged to the module's function work. Over the
  limit the variable is unknown of its declared type, keeps its marks, and is reported as
  `value_too_large` ("Variable value too large to convert"). A `--var` value too large to convert
  is kept as given and becomes unknown the same way, rather than an error.

## Consequences
- Positive:
  - The calls and variables above stop at the limit in milliseconds instead of taking seconds to
    minutes: a 40,000-element `tolist` took 82 s under parallel tests, and is now refused in
    under 0.1 s.
  - Below the limit, values are unchanged (TestConversionsMatchCty compares them with cty).
- Negative / accepted risks:
  - The estimate over-counts where cty does not unify: a tuple converted into `set(string)`, an
    object into `map(string)`, a list of tuples into a list of tuples, or a call whose conversion
    fails. A map or set variable of about 11,000 entries or more is therefore unknown even though
    converting it would have been linear (T-0114g).
  - Mixed types (tuples with a string, say) are charged per pair times the size of the largest
    type, since cty compares them element by element and tries each as the result (T-0114d
    review: 4,096 tuples of 64 numbers and a string took 13 s in a `list(any)` default).
    Homogeneous groups are charged per pair only, at every level of their columns.
  - Conditionals are still charged per result (ADR 0028): a result's nested tuples of different
    lengths unify together only with the other result in hand, so `true ? var.n : [["x"]]` over
    36 nested tuples still takes about 8 s (T-0114e).
  - Variables now draw on the module's function work, so a module with large typed variables has
    less left for its expressions.
  - `contains` and `index` compare the value with every element, walking the value each time, so
    `contains(var.t, var.t)` over 10,000 elements takes 21 s; that is not a conversion (T-0114h).
