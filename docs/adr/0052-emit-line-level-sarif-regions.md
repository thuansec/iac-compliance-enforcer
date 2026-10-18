# 0052 · Emit line-level SARIF regions and leave the run unnamed

- Status: accepted
- Date: 2026-10-18
- Task: T-0302
- Relates to: ADR 0045 (columns count hcl characters)

## Context
SARIF regions may carry columns, measured in the unit the run declares in `columnKind`:
`utf16CodeUnits` (the default) or `unicodeCodePoints`. iace's columns come from hcl, which counts
grapheme clusters (ADR 0045): a user-perceived character such as an emoji or a letter with a
combining accent is one column but several code points and UTF-16 units. Converting needs the
text of the line before the finding, which the loader does not keep after evaluation and which
reporters must not read (iace-reporting: reporters are pure functions of the report). Declaring
either column kind with grapheme columns would point GitHub at the wrong characters on any line
with such text before the finding.

## Decision
SARIF results carry line-level regions: `startLine` and `endLine`, no columns. The JSON report
keeps the exact grapheme-cluster columns. The SARIF reference's column conversion is not done.

Two more SARIF choices are made with it:
- **No `automationDetails`.** GitHub code scanning groups uploads by category; upload-sarif
  takes it from `automationDetails.id` when the file has one, else from its `category` input or
  the workflow, job and matrix key. A fixed id would make uploads from different jobs that scan
  different roots replace each other and close each other's alerts. The run is left unnamed so
  the upload decides.
- **URIs are relative to the directory iace ran in**, percent-encoded per path segment. GitHub
  needs repository-relative paths, so the action and the documented workflow run iace from the
  repository root (T-0501, T-0502).

## Consequences
- GitHub code scanning annotates whole lines; locations are never wrong, only less precise.
- Exact SARIF columns would need the loader to record UTF-16 columns (or line text) in the
  input document, an additive contract change left for when a consumer needs them.
- The iace-reporting SARIF reference's region example shows columns; its update joins T-0110b.
