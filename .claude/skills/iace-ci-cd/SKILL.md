---
name: iace-ci-cd
description: CI/CD for iac-compliance-enforcer (iace) — this repository's own GitHub Actions pipelines (lint, test, policy tests, vulnerability scan, cross-builds, releases with GoReleaser, SBOM, cosign signing, build provenance, signed policy-bundle publishing) and the pull-request enforcement product feature (composite GitHub Action, consumer workflows uploading SARIF to GitHub code scanning, required status checks and code-scanning merge protection via rulesets, Azure DevOps template). Use this whenever writing or reviewing any workflow, action.yml, release config or CI docs, pinning actions, or advising how a repository should gate merges on iace.
---

# CI/CD and PR enforcement

## Loop safety
Within `.claude/loop-policy.json`, the loop pushes **feature branches**, opens PRs, and merges
them once they are green, up to date and conflict-free (`docs/ci/branch-workflow.md`). The guard
hook enforces this. The loop never pushes `main` or tags, creates releases, edits repository
settings or rulesets, adds secrets, or runs `gh api` writes. Commands that change GitHub state
are written into docs for a human to run.

## This repository's merge gate
- Every change reaches `main` through a PR whose `ci-ok` check passed. `ci-ok` aggregates every
  CI job (`needs: [...]`, `if: always()`, success only when all needs succeeded), so it stays the
  single required check as jobs are added. **Never rename `ci-ok`** or drop a job from its `needs`:
  the guard's merge gate and the optional ruleset both key on it.
- CI runs on the PR merged with its base (the default `pull_request` checkout), with
  `IACE_GATES_BASE=origin/<base>` so the gates scan the whole PR diff.
- Server-side enforcement for everyone (PR required, `ci-ok` required, branch up to date, no force
  push) is the ruleset in `docs/ci/main-ruleset.json`. It needs GitHub Pro or a public repo.

## Workflow hardening rules (all workflows, ours and examples)
- **Pin every action to a full 40-char commit SHA** with a version comment:
  `uses: actions/checkout@<sha> # v5.0.0`. Resolve SHAs with `gh`, never from memory:
  ```bash
  gh api repos/actions/checkout/git/ref/tags/v5.0.0 --jq '.object | "\(.type) \(.sha)"'
  # if type is "tag" (annotated), dereference:
  gh api repos/actions/checkout/git/tags/<sha> --jq .object.sha
  ```
  Dependabot (`github-actions` ecosystem) keeps the pins current.
- Top-level `permissions: contents: read`. Grant more per job, only where needed.
- `actions/checkout` with `persist-credentials: false`.
- Never use `pull_request_target` or `workflow_run` with a checkout of PR code, and no secrets in
  jobs that run untrusted code. Fork PRs get a read-only token, which is correct; never "fix"
  that by escalating.
- No `${{ github.event.* }}` interpolated directly into `run:` scripts (script injection). Pass
  values through `env:` and quote them.
- Set `timeout-minutes` on every job, and a `concurrency` group with cancel-in-progress for PR workflows.
- Prefer OIDC (`id-token: write`) over long-lived secrets (cosign keyless, cloud auth).
- `actionlint` must pass. It runs in the gates once `.github/workflows` exists.

## This repository's pipelines
- **ci.yml** (PR + push to main) exists now with `gates` (hook tests plus `gates.sh full`) and
  `ci-ok`. T-0006 adds `lint` (golangci-lint, regal, actionlint), `test` (`go test -race
  -shuffle=on`, coverage gate), `policy` (`make policy-check policy-test`), `vuln`
  (`govulncheck ./...`), `build` (cross-compile matrix linux/darwin/windows × amd64/arm64 with
  `CGO_ENABLED=0 -trimpath`) and `e2e` (testscript), each a `make` target and each in `ci-ok`'s
  `needs`. Switch setup-go to `go-version-file: go.mod` with caching once go.mod exists.
- **selftest.yml** (M5): runs the composite action from this repo (`uses: ./`) against
  `testdata/e2e/*` and asserts the exit codes and SARIF content.
- **fixtures.yml** (nightly + manual, M6): `terraform validate` on every policy fixture for each
  supported provider major. It needs network (provider downloads), so it is not on the PR path.
- **release.yml** (tag `v*`) and **policy-release.yml**: [references/release.md](references/release.md).
- **dependabot.yml**: `gomod` (root and `tools/`), `github-actions`, weekly, grouped minor/patch updates.

## PR enforcement (the product feature)
Goal: every pull request in a consuming repository is scanned, results appear in GitHub code
scanning, and merging requires a passing check. The full templates (action inputs, consumer
workflow, ruleset JSON, Azure DevOps) are in [references/consumer-workflow.md](references/consumer-workflow.md).

Key behaviours of the composite action (`action.yml` at the repo root):
1. Install iace: release-binary mode downloads the pinned version for the runner's OS/arch and
   verifies its sha256 (and cosign/attestation once M11 ships). Until releases exist, it builds
   from source with setup-go at the action's ref.
2. Run `iace scan` with `-o sarif=<file> -o markdown=<summary file> -o github` and capture the exit code.
3. Append the Markdown to `$GITHUB_STEP_SUMMARY` and upload SARIF with
   `github/codeql-action/upload-sarif@<sha> # v4`, using `category`, even when the scan found
   issues (`if: always()` on those steps).
4. Exit with the scan's exit code **last**, so the check fails after results are published.

Gating options, documented for consumers:
- **Required status check** on the iace job via a repository ruleset. This works everywhere,
  including private repos without code scanning.
- **Code scanning merge protection**: a ruleset `code_scanning` rule with tool `iace` and alert
  thresholds. This needs code scanning, which on private or internal repos requires **GitHub
  Code Security** (decision D-04).
- Without code scanning, results still reach reviewers through the job summary and annotations
  (`-o github`, though GitHub caps the number shown per step).

AI suggestions in CI are off by default. If enabled, run them only on `push` or same-repo PRs,
with secrets or workload identity, never on fork PRs (no secrets there, and the prompt-injection
surface is larger).
