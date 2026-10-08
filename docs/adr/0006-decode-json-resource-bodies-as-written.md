# 0006 · Decode JSON resource bodies as written

- Status: accepted
- Date: 2026-10-08
- Task: T-0106d

## Context
In Terraform's JSON syntax, a property of a resource body is an argument or a nested block,
depending on the provider schema. Without a schema, a JSON object is ambiguous:
`"metadata_options": {"http_tokens": "required"}` is a nested block, and
`"tags": {"Name": "web"}` is a map argument, yet both are written the same way. A nested block
may also be written as an array of objects. The input document (ADR 0004) promises nested blocks
as arrays of objects, which is what HCL decoding and plan JSON produce. iace never has provider
schemas at scan time, and JSON configurations are common: CDK for Terraform generates them.

## Decision
This amends rule 1 of the input document (ADR 0004), "nested blocks are arrays of objects", for
resources written in JSON.

A resource body in JSON syntax is decoded with hcl's JSON support:
- `lifecycle`, `provisioner`, `connection` and `dynamic` are read as blocks, as Terraform does
  for every resource.
- Every other property is an attribute and keeps the shape it is written in. An object stays an
  object, and an array of objects stays an array of objects.
- So a nested block written as one object appears in `values` as an object, not as a
  one-element array. Its unknown and sensitive paths have that shape too:
  `["metadata_options", "http_tokens"]`, not `["metadata_options", 0, "http_tokens"]`.
- A value that holds a `"dynamic"` key with an object or array (a dynamic block inside a nested
  block) is unknown with a warning, because as data it would hide the blocks it generates.

Rules keep indexing nested blocks as in HCL (`["metadata_options", 0, "http_tokens"]`).
`iace.lib.tf`'s path helpers make that correct for both shapes:
- `value_or`, `is_unknown`, `is_sensitive` and `blocks` resolve an integer step 0 against an
  object as the object itself.
- For unknown and sensitive paths, the queried path is first rewritten against `values` in the
  same way, then compared with the recorded paths.
- `blocks(values, name)` returns an array for an array, a one-element array for an object, and
  an empty array when the key is absent. Every iteration over a nested block's entries goes
  through it: iterating `values.ingress[_]` or `some b in values.ingress` directly would walk an
  object's attribute values on JSON input and miss violations.

Map arguments such as `tags` are read directly, as in HCL. Attribute source ranges in JSON are
recorded for top-level properties only; a nested value points at its property.

## Alternatives considered
- Wrap every object in a one-element array, so blocks look like HCL. This breaks every map
  argument (`tags`, `labels`, `environment`), and those are among the most-checked values.
- Treat every object as unknown. That fails closed, but loses most of the coverage of generated
  JSON configurations: no tag, encryption or logging rule could ever pass or fail.
- Keep per-provider lists of block names. That needs provider schemas or a maintained list per
  provider version, which would drift silently. A wrong entry gives a wrong shape.
- Keep the shape but require every rule to read blocks through a helper: a rule that indexes
  `[0]` directly would still be wrong on JSON input, and nothing forces authors to use it.

## Consequences
- Positive: no guessing; maps and blocks both keep their values, and rules written for HCL and
  plan input stay correct on JSON input through the path helpers.
- Negative / accepted risks, if a rule reads a nested block without the helpers (for example
  `input.values.metadata_options[0]` directly):
  - false positives: a compliant JSON block reads as absent;
  - misjudged unknowns: an unknown nested value is not matched by an index-0 query, so it is
    judged as known (policy trap 1);
  - false negatives: rules of the form "absent is fine, present is bad".
- Mitigations:
  - the helpers above, and Regal or a lint test in T-0201 that rejects literal `[0]` indexing,
    `[_]` iteration and `some … in` over `values` paths in rule files, wherever it can tell a
    block path from a map path;
  - the fixture harness (T-0205) requires every rule to have a `.tf.json` fail fixture that
    writes its nested blocks as single objects, and one with an unknown nested value. This is
    enforced for every rule, including future ones.
- Follow-ups:
  - T-0201: the helpers and the lint;
  - T-0205: JSON fixtures for every rule;
  - T-0106e: dynamic blocks in JSON;
  - T-0110: the owner syncs the input-document reference with ADR 0004 and this amendment.
