# 0023 · Evaluate lookup without walking its map

- Status: accepted
- Date: 2026-10-09
- Task: T-0113e
- Amends: ADR 0020 (references passed to lookup)

## Context
`lookup` reads one element of a map, but as a cty function every call walks the whole map
several times:
- cty checks every argument for marks (ContainsMarked), and unmarks it deeply (UnmarkDeep)
  when the parameter does not accept marks;
- the bounded wrapper measures the arguments twice;
- the implementation checks that the whole map is known (IsWhollyKnown), as Terraform does.

Measured on a 300-entry map of objects (about 22,000 value units), one call cost about 124 ns per
unit of the map, against about 43 ns per unit for building a value. The common idiom
`{ for k in keys(local.m) : k => lookup(local.m, k, null).x }` therefore costs the map's size per
key, quadratic in the entries, and ADR 0020 charged the reference to the whole map again per
iteration. It reached a module's function work from about 140 entries (T-0113c), leaving every
value that used it unknown.

## Decision
- Every `lookup` call with two or three arguments in a syntax tree iace evaluates is renamed,
  when the tree is rewritten (rewriteForExprs, ADR 0020), to `__iace_lookup` (lookupFunction).
- `__iace_lookup` takes its arguments as expression closures and evaluates them itself, so cty
  sees only capsules and walks nothing. It reads the element in constant time and charges what it
  returns: 1 plus the result's size, measured up to the work left. Over the limit it returns
  unknown with the function_limit warning.
- Semantics, compared with Terraform:
  - Errors are the same, checked in Terraform's order, before any unknown makes the result
    unknown:
    - a null map or key;
    - a first argument that is not a map or object, or a key that is not a string;
    - a default that does not convert to a map's element type;
    - an object type without the key's attribute and no default, even when the object's value
      is unknown;
    - a missing key without a default;
    - more than three arguments.
  - Error messages never quote the key, which may be sensitive.
  - Marks: the result keeps the map's and the key's own marks and the element's marks. The
    earlier bounded lookup took on every sensitive mark anywhere in the map (more than
    Terraform). Now, as in Terraform, a non-sensitive element of a map that also holds a
    sensitive one is not sensitive.
  - Unknown values: Terraform returns unknown while any element of the map is unknown. iace
    returns a known element, which is what Terraform resolves to at apply. An unknown element,
    map or key is still unknown.
- ADR 0020's reference charge treats a reference passed as lookup's map like one the body only
  indexes: each iteration is charged its largest element, not the whole map.
- Lookups in templates that hcl parses at evaluation (nested .tf.json strings) still go through
  the bounded lookup.

## Alternatives considered
- Cache measured sizes per value: cty values have no identity to key a cache on, and cty's own
  walks would remain.
- Charge argument walks at a lower rate: the walks are real CPU (about 124 ns per unit per call),
  so the idiom stays quadratic, and charging less would let it run unbounded.
- Keep checking that the whole map is known: that walk is the cost being removed, and it only
  hides an element Terraform resolves to anyway.

## Consequences
- Positive: the idiom over 300 entries uses about 10% of a module's work, and a body that copies
  a whole 1,000-entry map on every iteration is still limited.
- Negative / accepted risks: lookup now marks only what Terraform marks, so iace no longer
  hides a non-sensitive element because another element is sensitive. A function error is
  reported as a call to `__iace_lookup`.
