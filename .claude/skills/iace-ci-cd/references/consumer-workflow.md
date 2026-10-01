# PR enforcement templates

`<sha>` placeholders must be resolved with `gh api` at implementation time (see SKILL.md). Never
invent a SHA.

## action.yml inputs and outputs
| input | default | meaning |
|---|---|---|
| `version` | the action's own ref | iace version to install (release-binary mode) |
| `path` | `.` | directories to scan (space-separated) |
| `config` | discover | path to `.iace.yaml` |
| `org-config` | — | org baseline path (trusted; e.g. checked out from the central repo) |
| `fail-on` | from config, else `high` | severity threshold |
| `sarif-file` | `iace.sarif` | where to write SARIF |
| `upload-sarif` | `true` | upload to code scanning (needs `security-events: write`) |
| `category` | `iace` | SARIF category; set a distinct one per root in monorepos |
| `annotations` | `true` | emit workflow annotations |
| `ai-fix` | `false` | opt-in AI suggestions (needs credentials; never on fork PRs) |

| output | meaning |
|---|---|
| `exit-code` | 0, 1 or 2 |
| `sarif-file` | path written |
| `blocking-count` | open findings ≥ fail-on |

## Consumer workflow (`examples/github/iace.yml`)
```yaml
name: iace
on:
  pull_request:
  push:
    branches: [main]          # default-branch analyses let code scanning tell "new in this PR" apart
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: iace-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    name: iace / scan        # the required status check context
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      security-events: write  # upload SARIF to code scanning
      actions: read           # required for private repositories
    steps:
      - uses: actions/checkout@<sha> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: thuansec/iac-compliance-enforcer@<sha> # vX.Y.Z
        with:
          path: .
          category: iace
```
Notes:
- `upload-sarif@v4` is current. v3 is deprecated as of December 2026 (GitHub changelog, Oct 2025).
- For fork PRs the token is read-only and the SARIF upload may be refused. The scan's own exit
  code still gates the PR, and the summary and annotations still show the results.
- Private consumer repos must be able to use actions from `thuansec/iac-compliance-enforcer`
  (organization setting "Access" for private actions), or consumers vendor the action.

## Rulesets (documented for humans to apply)
`docs/ci/required-checks.md` should contain:
```json
{
  "name": "iace required",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [
    {"type": "required_status_checks",
     "parameters": {"strict_required_status_checks_policy": false,
                    "required_status_checks": [{"context": "iace / scan"}]}},
    {"type": "code_scanning",
     "parameters": {"code_scanning_tools": [
        {"tool": "iace", "alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher"}]}}
  ]
}
```
```bash
gh api repos/OWNER/REPO/rulesets --method POST --input ruleset.json
```
Verify the field names and enum values against the current REST "Create a repository ruleset"
docs when writing this. Drop the `code_scanning` rule when the repository has no GitHub Code
Security.

## Monorepos
One job per root (matrix) with `path: <root>` and `category: iace-<root>`, or one job scanning
everything with a single category. Never use the same category for different roots: uploads
would overwrite each other's alerts.

## Azure DevOps (`examples/azure-pipelines/iace.yml`, optional)
- Install the pinned binary and verify its checksum, then run
  `iace scan -o junit=$(Build.ArtifactStagingDirectory)/iace.xml -o sarif=$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs/iace.sarif`.
- `PublishTestResults@2` with `testResultsFormat: JUnit`, `condition: always()`.
- Publish the `CodeAnalysisLogs` artifact (the SARIF SAST Scans Tab extension reads it).
- Branch policies → Build validation make the pipeline required for PRs.
