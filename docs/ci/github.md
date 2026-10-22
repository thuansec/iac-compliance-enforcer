# Scanning pull requests on GitHub

The iace action scans a repository's Terraform on every pull request. It never runs Terraform,
providers or modules. It shows the findings in three places:

- **the job summary**: pass or fail, counts per level, a table of open findings, and anything
  that was not fully checked;
- **workflow annotations** for open findings, shown inline on the files a pull request changes;
- **GitHub code scanning**, from an uploaded SARIF report.

The job then fails on the scan's result. It fails only after those results are published, so a
red check always comes with its explanation.

| exit code | meaning | check |
|---|---|---|
| 0 | no open finding at or above `high` | passes |
| 1 | at least one open finding at or above `high` | fails |
| 2 | the scan could not be trusted: a policy, parse or configuration error, a timeout, no Terraform under a path, or a refused input | fails |

## Set it up
1. Copy [`examples/github/iace.yml`](../../examples/github/iace.yml) to `.github/workflows/iace.yml`
   in the repository to scan.
2. Keep both `uses:` lines pinned to full commit SHAs. Let Dependabot (the `github-actions`
   ecosystem) propose updates rather than switching to a moving tag:
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: github-actions
       directory: /
       schedule:
         interval: weekly
   ```
3. Open a pull request that touches Terraform. The `iace / scan` check appears, and its findings
   show up in the job summary, the annotations and **Security → Code scanning**.
4. Make the check required so findings block merging. See *Gate merges* below.

The example runs on `pull_request` and on pushes to `main`. Code scanning compares a pull
request's alerts with the default branch's latest analysis, so the `push` run is what lets it
show only the alerts a pull request adds.

## Permissions
The workflow grants `contents: read` at the top level, and the scan job adds only what it needs:

| permission | why |
|---|---|
| `contents: read` | check out the code |
| `security-events: write` | upload SARIF to code scanning |
| `actions: read` | lets the SARIF upload read the workflow run in private repositories |

`actions/checkout` runs with `persist-credentials: false`, so the token is not left in
`.git/config` for later steps. Do not run the scan on `pull_request_target`: that would give
pull-request code a token with write access and the repository's secrets.

**Fork pull requests** get a read-only token, so the SARIF upload is refused, and a refused upload
fails the job even when the scan passed. Skip the upload for pull requests from forks; the scan's
exit code still gates them, and the summary and annotations still show the findings:

```yaml
        with:
          upload-sarif: ${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}
```

## Inputs and outputs
| input | default | meaning |
|---|---|---|
| `path` | `.` | directories to scan, separated by spaces or newlines, relative to the repository root |
| `category` | `iace` | code-scanning category of the upload; one per scanned root set (see *Monorepos*) |
| `sarif-file` | `iace.sarif` | where to write SARIF, relative to the repository root; it may not lead through a symlink |
| `upload-sarif` | `true` | upload to code scanning (needs `security-events: write`) |
| `annotations` | `true` | print workflow annotations for open findings |
| `version` | empty | an iace release such as `v1.2.3`, installed after its sha256 is checked; empty builds iace from the action's source at the pinned commit (the only mode until releases exist) |
| `ai-fix` | `false` | not available yet: `true` fails the step instead of being ignored |

| output | meaning |
|---|---|
| `exit-code` | the scan's exit code (0, 1 or 2); empty when the scan did not run |
| `sarif-file` | the SARIF path |
| `blocking-count` | open findings at or above `high` |

The fail-on threshold is fixed at `high` for now. Repository configuration (`.iace.yaml`), an org
baseline and a `fail-on` input are not available yet; until then they are left out of the action
rather than accepted and ignored.

Some behaviour to know about:
- iace runs from the repository root, so SARIF paths are repository-relative and code scanning
  can place every alert. This holds for one directory and for several.
- SARIF is uploaded only when the scan completed (exit code 0 or 1). A scan that exits 2 may
  have checked only part of the code, and uploading it would make code scanning close the
  alerts it missed. Any findings it did report (a parse error still writes a report) appear in
  the summary.
- GitHub shows a limited number of annotations per step. Code scanning and the SARIF file have
  every finding.

## Monorepos
Give each scanned root set its own category. Uploads that share a category replace each other's
alerts. One job per root:

```yaml
jobs:
  scan:
    name: iace / scan (${{ matrix.root }})
    strategy:
      fail-fast: false
      matrix:
        root: [infra/prod, infra/staging]
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: thuansec/iac-compliance-enforcer@89392da80651a6758e90a14aeb31912bf9a9d4c2 # main, 2026-10-22
        with:
          path: ${{ matrix.root }}
          category: iace-${{ matrix.root }}
```

Or scan everything in one job with a single category: `path: infra/prod infra/staging`.

With a matrix, the required check names each leg (`iace / scan (infra/prod)`). For a single
required check, add a job that always runs and fails unless every leg passed. A plain `needs:`
job is skipped when a leg fails, and **GitHub counts a skipped required check as passed**, so a
pull request with blocking findings could merge:

```yaml
  scan-ok:
    name: iace / scan
    needs: scan
    if: always()
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: {}
    steps:
      - name: Every scan leg passed
        env:
          RESULT: ${{ needs.scan.result }}
        run: test "$RESULT" = success
```

Required checks match the context name exactly, so `iace / scan` names only this job, not the
legs.

## Gate merges
There are two ways to block merging. Both are set with a repository ruleset on the default
branch:
- **Required status check** `iace / scan`. This works in every repository, including private
  ones without code scanning.
- **Code scanning merge protection**: a `code_scanning` rule for the tool `iace` with alert
  thresholds. It needs code scanning, which private and internal repositories get only with
  GitHub Code Security.

The ruleset JSON and the `gh api` commands are in `docs/ci/required-checks.md`, which is
planned.

## Private repositories
- Code scanning on private or internal repositories needs GitHub Code Security. Without it, set
  `upload-sarif: false` and rely on the summary, the annotations and the required status check.
- If the organization or enterprise restricts actions to an allowlist, add
  `thuansec/iac-compliance-enforcer` to it, or vendor the action into the repository. Under the
  default setting (all actions allowed), nothing is needed.

## Troubleshooting
| symptom | cause |
|---|---|
| `Resource not accessible by integration` on upload | the job lacks `security-events: write`, or the run is a fork pull request (skip the upload for forks, see *Permissions*) |
| exit code 2, "no Terraform root modules under this path" | `path` names a directory without `.tf` files |
| exit code 2, "sarif-file …" | `sarif-file` is absolute, contains `..`, or leads through a symlink |
| alerts from one root vanish after another job runs | two jobs upload with the same `category` |
| the summary says "could not be trusted" | a parse or policy error; the job log names the file |
