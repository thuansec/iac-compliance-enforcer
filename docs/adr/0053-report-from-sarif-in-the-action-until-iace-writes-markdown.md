# 0053 · Report from SARIF in the action until iace writes Markdown and annotations

- Status: accepted
- Date: 2026-10-22
- Task: T-0501
- Relates to: ADR 0052 (SARIF URIs, no automationDetails)

## Context
The composite action (`action.yml`) must write a job summary, workflow annotations and a
`blocking-count` output, upload SARIF, and only then fail on the scan's exit code. The
iace-ci-cd design runs `iace scan -o sarif=<file> -o markdown=<file> -o github`, but the
Markdown and GitHub-annotation formats (T-0304) and several outputs per run (T-0305) do not exist
yet; the action moved ahead of them for the pull-request demo (M12). Scanning twice (once for
SARIF, once for JSON) would double the scan time and could, in principle, report two different
results.

## Decision
The action scans once with `-o sarif` and derives the rest from that file with
`scripts/action/report.py` (Python standard library, run with `python3 -I`):
- **Summary**: pass/fail line, counts per SARIF level, excepted count, a table of at most 100
  open findings, and the run's tool execution notifications (coverage gaps, partial rule
  selections). Every value is Markdown-escaped and flattened to one line.
- **Annotations** (`annotations: true`): one `::error`/`::warning`/`::notice` per open result,
  file and line from the decoded URI; properties and messages are escaped per the workflow
  command rules, so text from scanned Terraform cannot start a command.
- **blocking-count**: open (not excepted) results at SARIF level `error`. This equals iace's
  blocking count only because the action has no `fail-on` input yet and iace defaults to `high`,
  whose severities (critical, high) are exactly the `error` level. T-0506, which adds `fail-on`,
  must take the count from the JSON report's `summary.blocking` instead.
- A missing or empty SARIF (a scan that exited 2 before writing) gives a "could not be trusted"
  summary and no `blocking-count`; a malformed one fails the step and writes nothing partial.
  When the scan never ran (a refused input, a failed install), the summary says so and no SARIF
  in the workspace is read: it would be stale or committed by the pull request.

The scan step (`scripts/action/scan.sh`) guards the workspace, which is a checked-out pull request:
- **SARIF upload only for exit code 0 or 1.** On parse errors iace still writes a report and
  exits 2; uploading that partial analysis would make code scanning close the alerts it misses.
  The summary still shows it.
- **No writes through symlinks.** `sarif-file` must be relative without `..`; a symlink among its
  directories is refused, and an existing file at the path (a committed symlink) is removed and
  the report written with noclobber, so a pull request cannot redirect the write outside the
  workspace.
- **Paths split on any whitespace, newlines included**, so a YAML block lists every directory.
- **A single path other than `.` is refused** (exit 2) until T-0302b: iace then writes SARIF URIs
  relative to that path, which code scanning cannot place.

Release-binary mode (`version: vX.Y.Z`) is `scripts/action/install-release.sh`: it downloads
`iace_<version>_<os>_<arch>.tar.gz` and `checksums.txt` from the release, checks the sha256 and
extracts only the binary. The asset names are those T-1101's GoReleaser config must produce;
attestation verification joins in M11. An empty `version` builds the action's own source.

`ai-fix: true` fails the step: an input that silently did nothing would look like a feature.

## Consequences
- The action needs `python3` on the runner (GitHub-hosted runners have it).
- When T-0304 and T-0305 land, the action switches to `-o markdown` and `-o github` and
  `report.py` is deleted; the summary's wording may change then.
- The summary and annotations are tested offline (`scripts/action`); the action as a whole runs
  only on a runner, in the self-test workflow (T-0503).
