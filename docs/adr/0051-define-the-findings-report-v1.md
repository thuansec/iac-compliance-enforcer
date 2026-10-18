# 0051 · Define the findings report v1

- Status: accepted
- Date: 2026-10-18
- Task: T-0301
- Relates to: the finding v1 contract (iace-architecture, findings-and-cli.md), ADRs 0048-0050

## Context
`iace scan -o json` is the first machine-readable report. CI tools, exception tooling and later
reporters (SARIF, JUnit, Markdown) build on it, so its shape, its encoding and how it may change
must be fixed before anything consumes it. The finding v1 contract lists the per-finding fields
and the report-level fields; the scan built so far adds report-level facts the contract does
not name (rule selection, hidden findings).

## Decision
- `schemas/findings.v1.json` (JSON Schema 2020-12, `additionalProperties: false` throughout)
  defines the report: `schema_version` "1", `tool`, `policy_sources`, `inputs`, `summary`,
  `findings`, `warnings`, `coverage_gaps`.
- Each finding carries every field of the finding v1 contract, including `policy_source`,
  `exception` and `ai_suggestion`. The last two are `null` until exceptions (M4) and AI fix
  suggestions (M10) exist; `attribute_path` is `null` when the violation names no attribute.
- `summary` counts findings by severity and by status (`open`, `excepted`), the blocking count
  and `fail_on`, and adds `min_severity`, `hidden`, `rules_evaluated` and `rules_loaded` so a
  filtered or partial run cannot read as a full one.
- Encoding is deterministic: struct fields in a fixed order, map keys sorted (encoding/json/v2
  `Deterministic`), lists sorted by the scan, two-space indentation.
- The built-in library's digest is `sha256:` and the hex SHA-256 over its files in lexical path
  order, each framed as path, NUL, decimal length, NUL, content, so a change to any file's
  content, name or the set of files changes it and no two framings collide.
- Evolution: within v1, new fields are added as optional properties (never `required`), so
  every older v1 report still validates against the newer schema; consumers validate with the
  schema of the version they were built for or a newer v1. Renaming or removing a field, or
  making one required, needs `schema_version` "2" and an ADR.

## Consequences
- Older consumers that validate strictly against an older v1 schema reject reports with fields
  added later; that is the price of `additionalProperties: false`, accepted to catch typos and
  drift in our own output.
- The findings reference in the harness gains the report-level fields above; it joins T-0110b.
