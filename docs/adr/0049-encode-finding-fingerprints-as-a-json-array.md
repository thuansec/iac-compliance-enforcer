# 0049 · Encode finding fingerprints as a JSON array

- Status: accepted
- Date: 2026-10-18
- Task: T-0204

## Context
The finding v1 contract (iace-architecture, findings-and-cli.md) defines the fingerprint as
`sha256(rule_id + root_module + resource.address + attribute_path)`. Exceptions and baselines
match findings by it, so it must never change for the same finding and never collide for
different ones. Taken literally, plain concatenation is ambiguous: `("IACE-AWS-S3-001",
"infra")` and `("IACE-AWS-S3-001i", "nfra")` concatenate alike, and `attribute_path` is an array
with no defined string form (an index 0 and a name "0" would look the same).

## Decision
The fingerprint is the lowercase hex SHA-256 of the compact JSON encoding of the array
`[rule_id, root_module, resource.address, attribute_path]`, where `attribute_path` is `null` when
the violation names none and otherwise a JSON array of strings (names) and integers (indexes),
as findings carry it. Line and column numbers stay out, so it survives edits above the resource.
`model.Fingerprint` implements it and a test pins one value.

## Consequences
- JSON strings delimit each part, and names and indexes encode differently, so distinct inputs
  never share an encoding.
- The value is part of the contract: changing the encoding invalidates stored exceptions and
  baselines and needs a new ADR and a finding schema major.
- The findings reference in the harness still shows the concatenation; its update joins T-0110b.
