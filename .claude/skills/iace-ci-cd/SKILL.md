---
name: iace-ci-cd
description: CI/CD for iac-compliance-enforcer (iace) — this repository's own GitHub Actions pipelines (lint, test, policy tests, vulnerability scan, cross-builds, releases with GoReleaser, SBOM, cosign signing, build provenance, signed policy-bundle publishing) and the pull-request enforcement product feature (composite GitHub Action, consumer workflows uploading SARIF to GitHub code scanning, required status checks and code-scanning merge protection via rulesets, Azure DevOps template). Use this whenever writing or reviewing any workflow, action.yml, release config or CI docs, pinning actions, or advising how a repository should gate merges on iace.
---

# CI/CD and PR enforcement

## Loop safety
The loop **writes** workflows, action metadata and docs, and validates them locally. It never
pushes, creates tags or releases, edits repository settings or rulesets, or adds secrets. Those
steps are for a human (the loop settings in BACKLOG enforce this). Commands that change GitHub
state are written into docs for the human to run.

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
- **ci.yml** (PR + push to main): jobs `lint` (golangci-lint, regal, actionlint), `test`
  (`go test -race -shuffle=on`, coverage gate), `policy` (`make policy-check policy-test`),
  `vuln` (`govulncheck ./...`), `build` (cross-compile matrix linux/darwin/windows ×
  amd64/arm64 with `CGO_ENABLED=0 -trimpath`), and `e2e` (testscript). Each runs a `make`
  target, so CI and the gates use the same commands. Use setup-go with go-version-file and caching.
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
