# iace progress log

Append-only. One entry per loop iteration; newest last. Format: .claude/skills/iace-loop/references/backlog-format.md

### 2026-10-01 · T-0001 · done
- What: bootstrapped the loop. This directory is now the working copy of
  github.com/thuansec/iac-compliance-enforcer (main tracks origin/main at 6b37a48). Created
  docs/plan/BACKLOG.md (seed roadmap M0–M11), this log and CLAUDE.md; extended .gitignore;
  committed .claude/ (iace-* skills, block-secrets hook, settings).
- Evidence: `git ls-remote` lists refs/heads/main; gh logged in as thuansec with a fine-grained
  token that **expires 2026-11-30 15:34:57 UTC**; loop_status.py shows T-0002 as next; gates full PASS.
- Tools found (user-level, ~/.local/bin unless noted): go 1.27.1, opa 1.21.1, regal v0.43.0,
  golangci-lint 2.14.0, govulncheck v1.8.0, actionlint v1.7.12; terraform 1.13.2, jq 1.7 (/usr/bin).
  Missing: none.
- Fix during bootstrap: gates.sh progress check now lists untracked files individually
  (`--untracked-files=all`), so new directories no longer hide an updated PROGRESS.md.
- Decisions: none taken; D-01…D-06 remain open in BACKLOG.
- Next: T-0002 (pin dev tools in tools/go.mod).

### 2026-10-01 · harness · done
- What: harness upgrade from the agent-architecture review. Added the guard hook (pushes,
  destructive git, privilege escalation, GitHub writes, a commit gate tied to the full-gates
  stamp), a PostToolUse formatter, the hook test suite (121 cases), the iace-reviewer subagent,
  path-scoped .claude/rules, the fresh-context runner (run-loop.sh), permissions allow/deny, and a
  subagent spawn depth of 1.
- Files: .claude/hooks/*, .claude/agents/iace-reviewer.md, .claude/rules/*, .claude/settings.json,
  iace-loop (SKILL.md, backlog-format.md, run-loop.sh), iace-quality-gates (gates.sh,
  tree-fingerprint.sh), iace-security SKILL.md, CLAUDE.md.
- Evidence: hook tests 121/121; gates full PASS with stamp; guard verified live in Claude Code.
- Decisions: a commit requires a gates stamp for the exact tree (plan files excluded); git push
  stays blocked while push_to_remote is no.
- Next: T-0002.

### 2026-10-01 · harness · done
- What: branch, PR and merge gate. Every change now goes feature branch → PR → CI (`ci-ok`) →
  merge only when the PR is green, up to date and conflict-free (squash). Added CI
  (`.github/workflows/ci.yml`: `gates` + `ci-ok` aggregator), the PR template,
  `.claude/loop-policy.json` (push/PR/merge permissions moved out of the editable BACKLOG), a
  content-based gates stamp (also gates pushes), a guard merge gate that verifies the PR with gh,
  harness protection (edits to `.claude/**` and CLAUDE.md ask a human), and a docs/ci ruleset for
  server-side enforcement.
- Files: .claude/hooks/guard-loop.py, tests/*, .claude/loop-policy.json, .claude/settings.json,
  iace-loop (SKILL.md, loop_status.py, run-loop.sh, backlog-format.md, roadmap.md),
  iace-quality-gates (gates.sh, tree-fingerprint.sh), .github/*, docs/ci/*, CLAUDE.md, docs/plan/BACKLOG.md.
- Evidence: hook tests 173/173; actionlint ok; gates full PASS with stamp; status script and
  runner checked with fake gh/claude.
- Decisions: GitHub Free on a private repo cannot enforce rulesets (API: "Upgrade to GitHub Pro
  or make this repository public"), so the merge gate is enforced client-side by the guard plus CI
  until the ruleset in docs/ci/main-ruleset.json can be applied.
- Next: push this branch and open the first PR so CI runs once; then T-0002.

### 2026-10-01 · decision · done
- Owner decision: stay on GitHub Free (no Pro, no paid GitHub features). The GitHub ruleset in
  docs/ci/main-ruleset.json is not used; the merge gate is the guard hook plus CI (`ci-ok`).
- Resolves D-04: no GitHub Code Security on this private repository, so no code scanning here.
  T-0504 documents the path without code scanning (job summary, annotations, required check).
- Next: first PR for the harness branch so CI runs end to end; then T-0002.

### 2026-10-01 · harness · done
- What: CI is read from the GitHub Actions API. The fine-grained token gets HTTP 403 from the
  checks and status APIs (`gh pr checks`, `statusCheckRollup`, `gh run watch` and plain `gh run view`,
  through annotations), so the first PR's merge would have been blocked by the gate. The merge gate now requires
  the latest pull_request run of every workflow for the head, and the `ci-ok` job, to have
  passed; unexpected API data blocks the merge (fails closed). New `ci_state.py` applies the same
  rule for the loop (`--wait`, exit 0 green / 1 red / 2 running / 3 unknown); `loop_status.py`
  shows it for loop PRs; iace-loop step 9 waits with it.
- Files: .claude/hooks/guard-loop.py, .claude/hooks/tests/run.sh, .claude/settings.json,
  iace-loop (SKILL.md, scripts/ci_state.py, scripts/loop_status.py), .claude/skills/README.md,
  docs/ci/branch-workflow.md.
- Evidence: hook tests 199/199 (29 merge-gate cases, each checking its block reason; 11 ci_state
  cases); ci_state.py on PR #1's head against the live API: passed (run 36896148899, gates and ci-ok).
- Next: merge PR #1 through the gate once CI is green on the new head; then T-0002.

### 2026-10-02 · T-0002 · blocked
- What: tried to pin golangci-lint v2.14.0, govulncheck v1.8.0, actionlint v1.7.12, regal v0.43.0
  and opa v1.21.1 (latest; opa stays at v1.21.1 under MVS) in one tools/go.mod. Go is go1.27.1 (ok).
  Two problems block it:
  1. One module graph cannot build all five tools. OPA/regal require github.com/gobwas/glob v1.0.0,
     and depguard (in golangci-lint) fails to compile with it (`undefined: glob.Glob`). actionlint
     v1.7.12 is built against go.yaml.in/yaml/v4 rc.3, and gosec (in golangci-lint) forces rc.6
     (`te.Errors[0].Error undefined`). Tried in the scratchpad: {golangci-lint, govulncheck} build
     together, actionlint fails alongside golangci-lint, {opa, regal} build together.
  2. `go tool -modfile=tools/go.mod` fails without a root go.mod ("cannot find main module, but
     -modfile was set"), and gates.sh runs actionlint that way as soon as tools/go.mod exists. A root
     go.mod with no packages fails the bootstrap gates (`go vet ./...`: no packages), so this needs
     T-0003's module first.
- Files: docs/plan/BACKLOG.md (T-0002 `[!]` needs-human, new D-07; T-0003 now depends on T-0001,
  T-0004 on T-0002 + T-0003), docs/plan/PROGRESS.md. No tools/go.mod committed.
- Evidence: commands and errors above; scratch modules were deleted.
- Review: plan-only change, no reviewer.
- Next: T-0003 (scaffold the module). The owner decides D-07 and updates gates.sh and the
  iace-go-standards skill (harness), then T-0002 resumes.

### 2026-10-02 · decision · done
- Owner decision D-07: each dev tool is pinned in its own module, tools/<tool>/go.mod
  (golangci-lint, govulncheck, regal, actionlint, opa), run from the repository root with
  `go tool -modfile=tools/<tool>/go.mod <tool>`. This keeps one tool's dependency conflicts from
  breaking another's build. opa's module pins exactly the OPA library version; regal's embedded OPA
  follows regal's own requirements.
- Files: iace-quality-gates (gates.sh runs actionlint from tools/actionlint/go.mod; SKILL.md tool
  and tidy-check rows), iace-go-standards (Toolchain section; golangci.yml asset), iace-opa-engine
  (SKILL.md, references/capabilities.md), iace-architecture (layout), iace-loop (SKILL.md rule 4,
  references/bootstrap.md, references/roadmap.md T-0002 seed and order), CLAUDE.md,
  docs/plan/BACKLOG.md (D-07 resolved; T-0002 unblocked with new acceptance, still after T-0003).
- Evidence: scratch modules, one per tool, with a root go.mod: all five tools print their version
  through `go tool -modfile=tools/<tool>/go.mod` (golangci-lint 2.14.0, govulncheck 1.8.0,
  actionlint 1.7.12, regal 0.43.0 with OPA 1.21.0, opa 1.21.1), and `go mod tidy -diff` is clean for each.
- Next: T-0003 (scaffold the module), then T-0002.

### 2026-10-02 · decision · done
- Owner decisions:
  - D-01: the repository license is Apache-2.0. T-0005 now adds the LICENSE file.
  - D-02: confirmed: the CLI is `iace` and the config file `.iace.yaml`.
  - D-05: Amazon Bedrock is the only approved AI provider; the first-party Claude API, Vertex AI
    and Foundry are not approved. iace uses anthropic-sdk-go's Bedrock Mantle client with
    `anthropic.claude-opus-5-5`; region and credentials come only from the AWS environment, never
    from `.iace.yaml`, so a pull request cannot redirect where code excerpts go. Bedrock has no
    `inference_geo` and no server-side refusal fallbacks. T-1004 is now the Bedrock provider;
    T-1008 (Bedrock and Vertex as optional providers) is superseded.
  - D-06: map to the CIS AWS Foundations Benchmark v5.0.0 and the CIS Microsoft Azure Foundations
    Benchmark v2.0.0, the newest versions with an official public mapping (AWS Security Hub; the
    Azure Policy initiative). The loop can verify every mapping without the CIS PDFs, and the IDs
    match what teams see in Security Hub and Defender for Cloud. Newer releases (AWS v7.0.0,
    Azure v6.0.0) need the PDFs and a new decision. Rules store CIS IDs only, never CIS text
    (licensed for non-commercial use only).
  - D-03 stays open. Its entry now explains the options; the planned environment secret is not
    available on GitHub Free for a private repository. Recommended: AWS KMS.
- Files: docs/plan/BACKLOG.md, iace-ai-remediation SKILL.md, iace-repo-policy
  references/config-schema.md, iace-cloud-controls references/frameworks.md, iace-architecture
  references/findings-and-cli.md (AI credentials row), iace-loop references/roadmap.md (T-0005,
  T-1004, T-1008 seeds).
- Evidence: AWS Security Hub CIS page (supports 5.0.0, 3.0.0, 1.4.0, 1.2.0; recommends 5.0.0);
  Microsoft Learn CIS Azure 2.0.0 initiative page (no 2.1.0 page); Defender for Cloud release
  notes (CIS Azure 2.1.0 GA, 3.0 preview); CIS Azure page (latest 6.0.0) and April 2026 update
  (AWS 7.0.0); GitHub docs (Free: environments only on public repositories); claude-api skill
  (Bedrock Mantle client, `anthropic.` model IDs, Bedrock feature availability).
- Next: T-0003.

### 2026-10-02 · decision · done
- Owner decision D-03: the policy-bundle signing key is an AWS KMS key (ECC_NIST_P256,
  SIGN_VERIFY) that never leaves KMS. Only policy-release.yml running for a `policies-v*` tag can
  sign: its IAM role trusts only GitHub OIDC tokens for those tags and may only `kms:Sign` with
  that key, so branch workflows (the loop's included) cannot sign. GitHub Free has no environments
  or tag protection for private repositories, so repository write access stays with the owner.
- Design: `opa build` can sign only with a local key file, so bundles are built unsigned and get a
  detached signature, `<bundle>.sig`: base64 of the DER ECDSA P-256 signature over the tarball's
  SHA-256 (`aws kms sign --message-type DIGEST`). iace checks it with `ecdsa.VerifyASN1` against the
  trust store before parsing the tarball (standard library only). T-0802 records it in an ADR.
- Backlog: T-0802 and T-0803 rewritten for this; new T-0808 (the owner creates the KMS key, the
  OIDC provider and the role; the loop commits the public key). New decision D-08: GitHub Free
  offers artifact attestations only for public repositories, and keyless cosign publishes the
  repository and workflow names, so the M11 release plan needs a public repository or KMS-signed
  checksums.
- Files: docs/plan/BACKLOG.md; iace-repo-policy references/policy-supply-chain.md; iace-ci-cd
  references/release.md; iace-security SKILL.md and references/threat-model.md (T5, T10);
  iace-loop references/roadmap.md (T-0802, T-0803, T-0808 seeds).
- Evidence: AWS KMS Sign API reference (DIGEST skips hashing; raw messages are limited to 4096
  bytes; ECDSA signatures are DER per RFC 3279, base64 in the CLI). Scratch round trip with an
  OpenSSL P-256 key signing the digest: the documented `openssl dgst -verify` command and Go's
  `ecdsa.VerifyASN1` accept the signature and both reject a tampered bundle. GitHub docs:
  attestations on Free, Pro and Team only for public repositories.
- Next: T-0003.
