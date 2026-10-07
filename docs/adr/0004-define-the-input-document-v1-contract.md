# 0004 · Define the input document v1 contract

- Status: accepted
- Date: 2026-10-07
- Task: T-0101

## Context
Every Rego rule reads one JSON document per root module (HCL mode) or plan file (plan mode). That
document is the contract between the Go loader and every built-in, central and org policy, so a
silent change to its shape breaks rules without a compile error. The same rule must work in both
modes, an unknown value must never look like a compliant one, and the output must be
byte-identical across runs for golden tests. The shape is specified in the iace-architecture
skill (`references/input-document.md`). This ADR records how the code and the schema pin it down.

## Decision
- `internal/model` holds the Go types (`InputDocument` and its parts). Struct field order is the
  JSON key order. Paths are `model.Path` (strings and non-negative integers) and instance keys are
  `model.InstanceKey` (null, a non-negative integer or a string); both reject anything else when
  decoding.
- `model.EncodeInput` is the only way to serialize a document. It uses `encoding/json/v2` with
  `Deterministic(true)`, so object keys are sorted and nil slices and maps encode as `[]` and
  `{}`, never `null`. `model.DecodeInput` rejects unknown members, duplicate names, invalid UTF-8
  and any `schema_version` other than `"1"`.
- `schemas/input.v1.json` (JSON Schema 2020-12) is the published contract. Every object except
  `values` sets `additionalProperties: false`; file paths must be relative, slash-separated and
  free of `..`. Tests prove the reference example decodes strictly and round-trips unchanged,
  that the schema accepts it, that a document setting every Go field validates (so no field
  exists in Go without the schema), and that malformed documents are rejected.
- Details the reference leaves open, fixed here:
  - `terraform.backend` is `null` when no backend is declared; `required_version` is `""`.
  - `source_range` (providers, module calls, outputs) and `source.module_call` are
    `{file, range}`, since a range is useless without its file.
  - `meta.lifecycle` holds only settings written in the configuration; `ignore_changes` lists
    dot-joined paths, and Terraform's `all` keyword is `"*"`.
  - A coverage gap's `file` is `""` and `line` is `0` when unknown.
  - `source.plan_file` is required in plan mode and forbidden in HCL mode.
  - Inside `values` (type `model.Values`) every nil, including a typed nil slice or map, encodes
    as `null`, because null means unknown; only a nil `values` map itself encodes as `{}`.
  - Numbers in `values` decode as float64; integers beyond 2^53 lose precision.
  - Decode errors name the JSON kind and pointer of a rejected value, never the value itself.
- Additive fields within v1 update the Go types, the schema, its tests and the reference together.
  Renames, removals and changes of meaning need `schema_version: "2"` and a new ADR.

## Alternatives considered
- `encoding/json` (v1): it encodes nil slices as `null`, so every producer would have to
  pre-fill every collection or policies would need null checks.
- A permissive schema (`additionalProperties` allowed): it would not catch drift between the Go
  types and the schema, and the schema already changes in the same commit as any new field.
- Generating the Go types from the schema: it adds a generator to the toolchain and produces
  weaker types (`any` for paths and keys) than the hand-written ones.

## Consequences
- Positive: one place to serialize, deterministic output, and drift between the types, the schema
  and the reference example fails a test.
- Negative / accepted risks: large integers in `values` lose precision; the reference document
  lives in the harness (`.claude/`), so the clarifications above must be copied there by a human
  (T-0110); a test keeps the testdata copy of its example identical to the reference.
- Follow-ups: T-0110 syncs the reference document; T-0109 builds documents from HCL and adds
  golden tests that validate against the schema.
