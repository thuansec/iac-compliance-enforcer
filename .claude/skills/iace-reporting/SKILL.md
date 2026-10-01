---
name: iace-reporting
description: How iace turns findings into outputs — the Reporter interface, deterministic ordering, the text/table, JSON (versioned schema), SARIF 2.1.0 for GitHub code scanning, JUnit XML, Markdown summary and GitHub annotation formats, multiple outputs per run, exit-code computation, coverage gaps, excepted findings, redaction, and golden tests. Use this whenever adding or changing an output format, touching internal/report, deciding what a user or CI system sees, or debugging why GitHub code scanning shows (or hides) an alert.
---

# Reporting

Reporters are pure: `Write(ctx, w io.Writer, r *model.Report) error`. They never compute
policy results, read files, or decide exit codes. That happens upstream, so every format tells
the same story.

## Report model (input to every reporter)
`model.Report` = tool info + policy sources (name, version, digest) + inputs scanned +
findings (open and excepted) + disabled rules + warnings (exceptions expiring, expired or stale,
deprecated rules) + coverage gaps + summary (counts by severity × status, blocking count,
`fail_on`). Fields are defined in `iace-architecture/references/findings-and-cli.md`.

## Rules for every format
- **Deterministic**: sort findings by severity (critical first), rule ID, file, start line,
  address. Sort every list. Timestamps come only from the injected clock, and golden tests fix it.
- **Never print sensitive values**: messages come from policies (which avoid values), and
  reporters never render `values` from the input document. Code snippets are off by default; if a
  format shows source lines (text `--show-source`, Markdown), lines overlapping `sensitive` paths
  are replaced with `<redacted>`.
- **Coverage gaps and warnings appear everywhere**, so a "clean" report that skipped half the
  repo is impossible to mistake for a clean repo.
- **Excepted findings stay visible**, separately counted, with exception ID, owner and expiry.
- **Paths** in outputs are relative to the repository root, slash-separated. For SARIF, compute
  them relative to the git toplevel when the scan root is a subdirectory.

## Formats
| format | purpose | key points |
|---|---|---|
| `text` (default) | humans in terminals | grouped by severity; `file:line  RULE-ID  address  message`; remediation line; summary table; colour only on a TTY without `NO_COLOR` |
| `json` | machines and archives | `schemas/findings.v1.json`; `schema_version: "1"`; stable key order (struct field order, no maps for top-level keys) |
| `sarif` | GitHub code scanning and other SARIF consumers | see [references/sarif.md](references/sarif.md); validated against the SARIF 2.1.0 JSON schema in tests |
| `junit` | Azure DevOps / Jenkins test tabs | `<testsuite name="iace">`; one `<testcase classname="<rule-id>" name="<address>">` per evaluated (rule, resource) with a finding; `<failure>` for open findings; `<skipped>` for excepted ones |
| `markdown` | `$GITHUB_STEP_SUMMARY`, PR comments | summary table by severity; top 50 open findings; collapsed details for the rest; an exceptions table; gaps; ≤ 1 MiB (the GitHub summary limit), truncated with a notice |
| `github` | workflow annotations | `::error file=…,line=…,endLine=…,title=<RULE-ID>::<message>` (critical/high), `::warning` (medium), `::notice` (low/info); property values escaped per the workflow-command rules (`%`, `\r`, `\n`, `:` and `,`). GitHub shows only a limited number of annotations per step, so the Markdown summary remains the complete list |

## Multiple outputs and files
`-o FORMAT[=PATH]`, repeatable. No path means stdout, and only one format may target stdout
(else a usage error). Write files atomically (temp then rename, 0644), and create parent
directories only if the flag says so (`--mkdir`). All outputs are produced from the same
`model.Report` in the same run. Reporters run after AI suggestions (if any) are attached.

## Exit code (computed in internal/app, applied in internal/cli)
- 2 if any error, or coverage gaps with `--fail-on-gaps`
- else 1 if any **open** finding has severity ≥ `fail_on`
- else 0

Write outputs **before** returning the exit code. CI must get the SARIF even when the scan fails.

## Golden tests
- `internal/report/<format>/testdata/*.golden`, generated from a fixed `model.Report` fixture
  covering every status, severity, gap and warning type, a finding without a location, a
  resource in a module, and unicode in messages.
- Regenerate with `go test ./internal/report/... -update`, then review the diff like code.
- Extra checks: SARIF validates against the vendored schema; JUnit parses with `encoding/xml`;
  JSON validates against `schemas/findings.v1.json`; Markdown length cap; annotation escaping table.
