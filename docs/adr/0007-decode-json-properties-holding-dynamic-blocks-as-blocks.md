# 0007 · Decode JSON properties that hold dynamic blocks as blocks

- Status: accepted
- Date: 2026-10-08
- Task: T-0106e
- Amends: ADR 0006

## Context
ADR 0006 keeps every property of a JSON resource body in the shape it is written in. It made a
value holding a `"dynamic"` key unknown until dynamic blocks in JSON could be expanded. T-0106e
expands them, as hcl's `dynblock` does for Terraform. A dynamic block can sit at the top of a
resource body, in a dynamic block's `content`, or inside a nested block written as a JSON object.
In the last case the property holding it can only be a nested block, because a map argument
cannot hold a block.

## Decision
- A JSON property is decoded as nested blocks, through hcl's schema-based block decoding (an
  object is one block, an array of objects one block per element), when either:
  - its source holds an object with a `"dynamic"` key whose value is an object or an array, at
    any depth, or
  - it has the same type as a dynamic block in the same body.
  Such a property appears in `values` as an array, even when written as one object. Detection
  reads the source and does not evaluate it, so iterators that are only in scope inside the
  block do not matter.
- Every other property keeps the shape it is written in, as ADR 0006 decides.
- Attribute source ranges are recorded inside properties decoded as blocks, under their entry
  paths (`setting.0.rule.0.port`). Elsewhere they stay at the top-level property.
- Static and dynamic entries of one type merge in source order, as `dynblock` does.
- A property that holds a dynamic block but is not an object or an array of objects is unknown,
  with an `invalid_expansion` warning.

## Alternatives considered
- Keep such properties unknown (ADR 0006): that fails closed, but it loses every rule over
  security-group rules and similar blocks in generated JSON, which use dynamic blocks heavily.
- Keep the written shape (an object) and expand only inside it: the entries would mix block and
  map semantics, and the property is certainly a block.

## Consequences
- Positive: dynamic blocks in JSON are checked like those in HCL, including iterator scope and
  limits.
- Negative / accepted risks: the same block type can be an object in one resource (no dynamic
  block) and an array in another. The path helpers of ADR 0006 already accept both shapes.
- Follow-ups: T-0110 (the input-document reference also states this amendment).
