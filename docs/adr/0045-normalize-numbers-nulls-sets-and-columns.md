# 0045 · Normalize numbers, nulls, sets and columns into the input document

- Status: accepted
- Date: 2026-10-17
- Task: T-0109
- Amends: ADR 0004

## Context
Turning an evaluated resource (a cty value with marks and unknown paths) into the input
document's `values` raises four questions the contract left open or answered in a way the parser
cannot meet:
- **Numbers.** cty numbers are arbitrary-precision floats. ADR 0004 says numbers decode as
  float64, but not how they are encoded. Exact decimal formatting costs about the square of a
  number's precision (ADR 0043: 2.4 ms at 8,192 bits), and a crafted value can hold many such
  numbers, so normalization must not format them exactly.
- **Nulls.** Contract rule 2 says null means unknown, while Terraform treats an attribute set to
  `null` as not set.
- **Sets.** cty addresses a set element by its value, so a path into a set has no index that a
  policy could follow.
- **Columns.** The reference and the schema say columns count bytes. hcl counts characters
  (grapheme clusters) in native syntax, and the parser drops each file's bytes after evaluation
  (ParsedModule.src), so byte columns cannot be recovered without keeping every file in memory.

## Decision
`terraform.NormalizeResource` applies these rules:
1. **Numbers.** An integer that fits in int64 is encoded exactly. Any other number is rounded
   to float64 (`big.Float.Float64`), in time linear in its precision. A number outside float64's
   range, or a non-zero number that rounds to zero, is **unknown**: null and listed in `unknown`,
   never a different number. Negative zero is encoded as 0.
2. **Nulls.** A known null object attribute is omitted (absent, rule 3), unless an unknown path
   names it, which makes it null. A known null list element or map element stays null, since its
   position or key is data; this is the only null in `values` that is not listed in `unknown`, so
   policies must read unknowns from the `unknown` list (`tf.is_unknown`), never from null.
3. **Sets** encode as arrays in cty's order. A set that holds any unknown value is unknown as a
   whole, and an unknown or sensitive path that steps into a set is reported as the set's path.
   Paths are converted by following the value's type, so a set element is never mistaken for a
   map key.
4. **Unknown paths** are the union of the evaluator's list and every unknown the walk meets, so
   an unknown the evaluator did not list is still reported (fail closed); only the outermost
   paths are kept, sorted with an index before a name.
5. **Whole value.** A path must have a step (schema `minItems: 1`), so a resource whose value is
   not a known object, or whose unknown paths include the whole value (the evaluator collapses
   more than 1024 unknown paths into the empty one) or a path the value cannot hold, cannot be
   described by paths. `NormalizeResource` then returns `complete = false`, and the caller
   records a coverage gap (T-0109d). A sensitive mark on the whole value marks every attribute.
6. **Columns** are hcl's: native syntax counts characters, not bytes. This amends the contract's
   "columns count bytes" in ADR 0004's reference and in the schema's range description.

## Alternatives considered
- Exact decimal text for every number (`json.Number`): precise, but formatting cost grows with
  precision squared and would need its own budget; ADR 0004 already decodes numbers as float64.
- Byte columns: correct for UTF-8 offsets, but needs every file's bytes after evaluation, about
  the size of the parse budget again (ADR 0016).
- Encoding sets with unknown elements partly known: the elements have no stable index, so a
  policy could not tell which element was unknown.

## Consequences
- Positive: normalization cost is linear in the value's size and precision; every unknown and
  every out-of-range number is reported, never guessed.
- Negative / accepted risks: integers beyond int64 and fractions beyond 17 significant digits
  lose precision; columns differ from byte offsets on lines with non-ASCII text before the
  position, which reporters must convert where a format needs bytes or UTF-16 units (SARIF).
- Follow-ups: the input-document reference in the iace-architecture skill (harness) needs the
  owner to state rules 1–6 and the column unit (T-0110b).
