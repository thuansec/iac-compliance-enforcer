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

### 2026-10-02 · decision · done
- Owner decision D-08: the repository becomes public before the first release, so the M11 release
  plan stays as written (keyless cosign signatures and GitHub build-provenance attestations, which
  on GitHub Free both need a public repository).
- Not done: the visibility switch itself. It is outward-facing and cannot be undone (clones and
  forks keep the history), so it is the needs-human step of the new T-1107, after the security
  sign-off (T-1105) and before the v0.1.0 release (T-1106 now depends on T-1107).
- Found while checking: the owner's personal email is the author of the two early commits on
  `main` and of the commits behind every loop pull request so far (GitHub keeps
  `refs/pull/N/head` after branches are deleted); squash merges use the GitHub noreply address.
  All of it becomes public with the repository. T-1107 reports this before the switch.
- Files: docs/plan/BACKLOG.md (D-08 resolved, no decisions open; T-1107; T-1106 depends on
  T-1107), iace-ci-cd references/release.md (policy attestation step guarded on a public
  repository), iace-loop references/roadmap.md (T-1106, T-1107 seeds).
- Next: T-0003.

### 2026-10-02 · T-1107 · blocked
- What: the owner made the repository public (D-08), earlier than T-1107 planned. Checked
  everything that became visible: all 17 commits on `main` and on the 6 pull-request refs. The
  gates' credential patterns match only 12 test fixtures marked `iace:fake-secret` (all obviously
  fake), gitleaks v8.30.1 finds no leaks, and commit messages are clean. 10 commits carry the
  owner's personal email address; the rest use the GitHub noreply address.
- Settings: none applied yet (no rulesets; private vulnerability reporting off; the loop's token
  cannot read the Dependabot, fork-approval or workflow settings). docs/security/going-public.md
  lists each with its command. The new docs/ci/tags-ruleset.json makes `v*` and `policies-v*` tags
  immutable, and docs/ci/branch-workflow.md now says the `main` ruleset can be applied.
- Files: docs/security/going-public.md, docs/ci/tags-ruleset.json, docs/ci/branch-workflow.md,
  docs/plan/BACKLOG.md (T-1107 `[!]` needs-human), iace-repo-policy
  references/policy-supply-chain.md, iace-ci-cd references/release.md, iace-security
  references/threat-model.md (private-repository premises removed).
- Next: the owner applies the settings; the loop continues with T-0003.

### 2026-10-02 · T-1107 · blocked
- What: the owner imported both rulesets. Read back through the API: "main: pull requests with
  green CI" (24364215) and "release tags are immutable" (24364226), both active with no bypass
  and matching docs/ci; the effective rules on `main` are deletion, non_fast_forward,
  pull_request and required_status_checks (`ci-ok` from GitHub Actions, strict).
- GitHub added `require_extra_approval_for_unattributed_changes: true` to the pull-request rule. The
  loop's commits on pull requests #5 to #7 are attributed to the owner's account, so it does not
  block loop merges; docs/ci/main-ruleset.json now states it, and the docs explain it.
- Still to apply: secret scanning with push protection, private vulnerability reporting (still
  off), Dependabot alerts, approval for outside contributors' workflows.
- Files: docs/ci/main-ruleset.json, docs/ci/branch-workflow.md, docs/security/going-public.md,
  docs/plan/BACKLOG.md.
- Next: this is the first pull request merged under the ruleset; then T-0003.

### 2026-10-02 · T-1107 · done
- What: the owner applied the remaining settings. Read back through the API: private
  vulnerability reporting is on, and both rulesets are active. Secret scanning with push
  protection, Dependabot alerts and approval for outside contributors' workflows are on per the
  owner; the loop's fine-grained token cannot read them (HTTP 403).
- Files: docs/security/going-public.md (status column), docs/plan/BACKLOG.md (T-1107 done).
- Evidence: `gh api` reads of `private-vulnerability-reporting` ({"enabled":true}) and `rulesets`
  (both active).
- Review: docs and plan only, no reviewer.
- Next: T-0003.

### 2026-10-02 · T-0003 · done
- What: the Go module and the first command. go.mod declares go 1.27.0 with toolchain go1.27.1.
  cmd/iace/main.go only calls cli.Main. internal/cli has Run (args → exit code: 0 ok, 2 on any
  error, one line on stderr) and Main, the only os.Exit, plus `version [--json]`. internal/version
  holds Version/Commit/Date, which only `-ldflags -X` sets (default "dev"), and the JSON document
  (schema_version "1", name, version, commit, date).
- Dependencies: spf13/cobra v1.10.2 (Apache-2.0, released 2025-12) and rogpeppe/go-internal v1.16.0
  (BSD-3, released 2026-07, tests only); indirect pflag (BSD-3), mousetrap (Apache-2.0), x/sys and
  x/tools (BSD-3). All pure Go (stdlib `net` comes in through pflag; releases build with
  CGO_ENABLED=0); govulncheck: no vulnerabilities.
- Files: go.mod, go.sum, cmd/iace/{main.go,main_test.go,testdata/script/*.txtar},
  internal/cli/{cli.go,version.go,cli_test.go}, internal/version/{version.go,version_test.go}.
- Evidence: every test failed against empty stubs first; `go test -race -shuffle=on -count=1 ./...`
  passes; coverage 95.6%; the write-error test is mutation-checked (swallowing the error fails
  it); TestLdflagsInjection builds the binary with -trimpath and -X and reads the values back;
  `go mod tidy -diff` clean; gates full PASS (bootstrap fallback until T-0004).
- Review: iace-reviewer APPROVE with four minor findings. Fixed here: cobra's lazily added `help`
  command had no Example (the test now creates it and it has one), and Run(nil) read os.Args
  (cobra's fallback; a helper-process test proves it no longer does). Recorded: flag values echoed
  in usage errors (new acceptance bullet on T-0206, before `--var` exists) and the `version
  --json` contract doc (T-0008, needs-human: harness file).
- Next: T-0002 (pin each dev tool in its own module).

### 2026-10-02 · T-0008 · done
- What: the owner approved the harness edit. iace-architecture references/findings-and-cli.md now
  documents `iace version`: the text line, the `--json` document (key order, "dev" defaults,
  `-ldflags -X` injection) and its schema_version rules (adding a field keeps "1"; renaming or
  removing one needs "2" and an ADR), and that a bare `iace` prints help and exits 0. The same
  skill's project identity no longer calls the repository private.
- Files: .claude/skills/iace-architecture/references/findings-and-cli.md,
  .claude/skills/iace-architecture/SKILL.md, docs/plan/BACKLOG.md.
- Evidence: the documented output matches internal/cli and the testscript `want.json` from T-0003.
- Review: docs only, no reviewer.
- Next: T-0002.

### 2026-10-02 · T-0002 · done
- What: each dev tool is pinned in its own module (D-07): tools/golangci-lint (v2.14.0),
  tools/govulncheck (x/vuln v1.8.0), tools/actionlint (v1.7.12), tools/regal (v0.43.0) and
  tools/opa (v1.21.1). Go is go1.27.1. The opa CLI version is the one the OPA library must use
  when the engine lands (M2); regal resolves its own embedded OPA (v1.21.0), which need not match.
- Files: tools/{golangci-lint,govulncheck,actionlint,regal,opa}/{go.mod,go.sum}.
- Evidence: before pinning, `go tool -modfile=tools/<tool>/go.mod <tool>` failed for all five
  (no such file); afterwards each prints its version from the repository root. `go -C
  tools/<tool> mod tidy -diff` is clean and `mod verify` passes for every module. `go list ./...`
  still lists only the three product packages. `gates.sh full` passes with no actionlint on PATH
  (PATH limited to system dirs plus GOROOT/bin), so it ran actionlint from tools/actionlint/go.mod.
- Review: no code, tests, policies, workflows or hooks; no reviewer.
- Next: T-0004 (Makefile, golangci-lint config, editor config). CI still installs actionlint with
  `go install`; T-0006 can drop that step now that the gates use the module.

### 2026-10-02 · T-0004 · done
- What: the Makefile is now the single source of commands. It has the nine contract targets
  (fmt-check, lint, test, cover-check, policy-check, policy-test, vuln, build, tidy-check), `ci`
  running them in order, plus `fmt`, `tools` and a `help` default; tools run through their
  pinned modules. Policy and Terraform steps skip with a message until policies/ and testdata/
  exist. .golangci.yml is the iace-go-standards asset, except gofumpt's `extra-rules: true`,
  which golangci-lint v2.14 deprecates, now `extra: {group-params: true}`. .editorconfig covers
  Go, Makefile, Rego, shell, Python, YAML, JSON, Markdown and Terraform.
- Lint fixes: three tests started subprocesses without a context (noctx); they now use
  exec.CommandContext(t.Context(), …).
- Files: Makefile, .golangci.yml, .editorconfig, cmd/iace/main_test.go, internal/cli/cli_test.go.
- Evidence: before, `make ci` had no rule and `golangci-lint config verify` exited 6. Probe:
  `golangci-lint fmt --diff` exits 1 on a misformatted file and 0 on clean code (fmt-check also
  fails on any output). Now: config verify OK; `make ci` passes (0 lint issues, coverage 95.6%,
  govulncheck clean); `make tools` builds all five tools; gates full runs every contract target
  through make and passes.
- Review: iace-reviewer APPROVE with three minor findings. Fixed: `make tools` failed open (a
  failing tool before the last one still exited 0; reproduced, now exits non-zero) and
  .editorconfig lacked shell (tabs) and Python (4 spaces) sections. Recorded: T-0009
  (needs-human) to update the harness asset's deprecated gofumpt key.
- Next: T-0005 (ADRs and docs skeleton). T-0006 should drop CI's separate `go install
  actionlint` step: `make lint` runs the pinned actionlint, and gates.sh then skips its own.

### 2026-10-02 · T-0005 · done
- What: the first three ADRs and the project's front door. ADR 0001 adopts ADRs (template,
  sequential numbers, immutable, contract changes land with their ADR). ADR 0002 embeds OPA via
  the v1 `rego` package (not `sdk`, not a subprocess), with the `opa` CLI pinned to the library
  version. ADR 0003 analyzes Terraform statically and never executes it (plan JSON only as an
  opt-in input from trusted pipelines). The README covers purpose, status, a quickstart
  placeholder, links, private vulnerability reporting and the license. CONTRIBUTING covers
  prerequisites, the make targets, how a change lands, the ground rules and the loop. LICENSE is
  the Apache-2.0 text (D-01).
- Files: docs/adr/0001-record-architecture-decisions.md,
  docs/adr/0002-embed-opa-via-the-v1-rego-package.md,
  docs/adr/0003-analyze-terraform-statically-never-execute-it.md, README.md, CONTRIBUTING.md,
  LICENSE.
- Evidence: LICENSE fetched from apache.org and cross-checked against the Apache-2.0 LICENSE of
  github.com/inconshreveable/mousetrap in the module cache (identical apart from its filled-in
  appendix example); every relative link in README and CONTRIBUTING resolves; the quickstart
  commands run.
- Review: docs only, no reviewer.
- Next: T-0006 (extend CI with the full Go and OPA jobs; drop the separate actionlint install).

### 2026-10-02 · T-0006 · done
- What: CI now runs the full set of checks as separate jobs, all through make and all in
  `ci-ok`'s needs: lint (`make fmt-check lint`), test (`make test cover-check`, which also runs
  the testscript e2e suite), policy-test (`make policy-check policy-test`, a no-op until M2), vuln
  (`make vuln`), and build (linux/darwin/windows × amd64/arm64, `make build` with GOOS/GOARCH).
  `gates` stays for loop parity, without its separate `go install actionlint` step (`make lint`
  runs the pinned actionlint). setup-go reads `go.mod` (the toolchain line wins, so go1.27.1),
  and each job keys its cache on the go.sum files of what it builds. .github/dependabot.yml
  updates gomod (`/` and `/tools/*`) and github-actions weekly, with minor and patch grouped.
- Files: .github/workflows/ci.yml, .github/dependabot.yml, docs/plan/BACKLOG.md (T-0202 gains a
  bullet: the OPA library and tools/opa move together, with a test and Dependabot grouping).
- Evidence: checkout v7.0.1 and setup-go v7.0.0 are the latest releases, and `gh api` resolved
  both tags to the pinned commit SHAs (lightweight tags). setup-go's README and advanced-usage doc
  at that commit confirm the toolchain directive and multi-line cache paths. actionlint passes;
  all 12 `uses:` are pinned with version comments; 6/6 checkouts use persist-credentials: false;
  every job has a timeout; ci-ok needs every other job (parsed with PyYAML); all six cross-builds
  pass locally. GitHub's docs confirm `directories` accepts globs.
- Review: iace-reviewer APPROVE with three minor findings. Fixed: a single shared cache key meant
  only the first job to finish (usually one that builds nothing) saved the cache, so each job now
  has its own key and the build matrix doesn't cache; Dependabot listed tool directories by hand,
  now `/tools/*`. Recorded: T-0009 (needs-human) now also updates the iace-ci-cd skill's job list
  (`policy-test`, e2e inside `test`). Local actionlint ran without shellcheck (not installed);
  the first CI run shellchecks the `run:` scripts.
- Next: T-0007 (security baseline documents).

### 2026-10-02 · T-0007 · done
- What: the security baseline. SECURITY.md sends reports to GitHub's private vulnerability
  reporting, lists what to include (fake values only) and the scope, and states that there is no
  release yet; it makes no response-time promise, which would be the owner's to give.
  .github/CODEOWNERS makes @thuansec the owner of everything (the ruleset doesn't require
  code-owner review, so loop pull requests still merge). docs/security/threat-model.md adapts
  the iace-security seed: assets now include the development harness (A7) and the AI loop as an
  actor; every mitigation says whether it is in place or planned in a milestone; new T13 covers
  the AI development loop (hooks, harness approval, reviewer agent, `main` ruleset, owner-only
  tags). The README links SECURITY.md.
- Files: SECURITY.md, .github/CODEOWNERS, docs/security/threat-model.md, README.md.
- Evidence: every relative link in SECURITY.md, the threat model and the README resolves; the
  statuses match the backlog (the T10 and T11 controls and the rulesets are live).
- Review: docs only, no reviewer.
- Next: M0's last open task is T-0009, which needs the owner (two harness edits); then the M0
  wrap-up.

### 2026-10-02 · T-0009 · done
- What: the owner approved two harness edits found in review. The iace-go-standards golangci asset
  uses gofumpt `extra: {group-params: true}` instead of the deprecated `extra-rules: true`, so
  .golangci.yml's body is identical to the asset again (its explanatory comment is gone). The
  iace-ci-cd skill lists the CI jobs as ci.yml has them (`policy-test`, e2e inside `test`,
  per-job cache keys) and says the `main` and release-tag rulesets are active.
- Files: .claude/skills/iace-go-standards/assets/golangci.yml, .claude/skills/iace-ci-cd/SKILL.md,
  .golangci.yml.
- Evidence: the asset and the repo config both pass `golangci-lint config verify`, and their
  bodies diff clean; `make lint`: 0 issues, no deprecation warning.
- Review: harness and docs only, approved by the owner; no reviewer.
- Next: M0 wrap-up (every M0 task is done).

## Milestone M0 complete · 2026-10-02
- Works now:
  - Go module (go 1.27.0, toolchain go1.27.1) with `iace version [--json]`; internal/cli maps
    outcomes to the contract's exit codes (0, or 2 with one line on stderr).
  - Dev tools pinned one module per tool under tools/ (golangci-lint v2.14.0, govulncheck v1.8.0,
    actionlint v1.7.12, regal v0.43.0, opa v1.21.1), run with `go tool -modfile`.
  - The Makefile contract (fmt-check, lint, test, cover-check, policy-check, policy-test, vuln,
    build, tidy-check, plus ci, fmt, tools); gates.sh runs it before every commit.
  - CI: gates, lint, test, policy-test, vuln and a six-platform build, aggregated by `ci-ok`;
    actions pinned by SHA; Dependabot for gomod and actions.
  - The public repository is protected: the `main` ruleset (pull request, green `ci-ok`, up to
    date, squash only, no bypass), immutable release tags, secret scanning with push protection,
    private vulnerability reporting, Dependabot alerts, approval for outside contributors' runs.
  - Docs: ADRs 0001-0003, README, CONTRIBUTING, Apache-2.0 LICENSE, SECURITY.md, CODEOWNERS, the
    threat model, and owner decisions D-01 to D-08.
- Try it: `make tools && make ci`; `go run ./cmd/iace version --json`;
  `bash .claude/skills/iace-quality-gates/scripts/gates.sh full`.
- Known gaps:
  - No scanning yet: the static Terraform loader is M1 (T-0101 to T-0109), the engine M2.
  - Usage errors echo flag values; fixed before `--var` exists (T-0206 bullet).
  - The OPA library and tools/opa must move together; check and Dependabot grouping in T-0202.
  - Makefile targets `capabilities` (T-0201), `policy-bundle` (T-0802) and `snapshot` (T-1101)
    arrive with their tasks; policy signing needs the owner's AWS setup (T-0808).
  - The owner's personal email is on early commits and pull-request refs: the owner's call, so
    no follow-up task (docs/security/going-public.md).
- Next: M1 is awaiting the owner's approval; set its status to `active` in BACKLOG to continue.

## 2026-10-07 · M1 · approved
- What: the owner approved milestone M1; its status moves from `awaiting-approval` to `active`.
- Files: docs/plan/BACKLOG.md, docs/plan/PROGRESS.md
- Evidence: plan-only change; `gates.sh full` green.
- Review: plan only, approved by the owner; no reviewer.
- Next: T-0101.

## 2026-10-07 · T-0101 · done
- What: the input document v1 contract in code. internal/model has the Go types, `Path` and
  `InstanceKey` with strict JSON, a `Values` type whose nils encode as null (unknown), and
  `EncodeInput` (json/v2, sorted keys, no null collections) and `DecodeInput` (rejects unknown
  members and other schema versions). schemas/input.v1.json is strict (`additionalProperties:
  false`, relative slash paths, plan_file only in plan mode). ADR 0004 records the decisions.
- Files: internal/model/{doc,input,path,values,codec}.go, internal/model/input_test.go,
  internal/model/testdata/input-example.json, schemas/input.v1.json,
  docs/adr/0004-define-the-input-document-v1-contract.md, go.mod, go.sum
- Evidence: `gates.sh full` 13 pass (1 warn: progress, now written); internal/model coverage
  92.5%. The reference example decodes, round-trips unchanged and validates; a document setting
  every Go field validates (drift check); 20 malformed documents are rejected; decode errors do not
  quote values. New deps: santhosh-tekuri/jsonschema/v6 v6.0.3 (Apache-2.0, maintained, pure Go)
  and google/go-cmp v0.7.0 (BSD-3), both test-only so far.
- Review: iace-reviewer APPROVE with 5 minor findings. Fixed four: typed nils in values now
  encode as null, decode errors name only the JSON kind, a test pins the example to the reference,
  and plan_file is tied to plan mode. The decoder doc now says the schema is the authority.
  The fifth (sync the harness reference) is T-0110, blocked needs-human.
- Next: T-0102 (discover root modules safely).

## 2026-10-07 · T-0102a · done
- What: T-0102 was split into T-0102a (this: walk the scan root safely) and T-0102b (root vs
  child modules). New internal/fsutil wraps os.Root: reads stay inside the scan root, files open
  with O_NONBLOCK on unix and are checked on the open handle (a FIFO can neither hang nor be
  read), reads are capped with a growth check, and errors quote the path and drop the raw path
  of *fs.PathError. terraform.Discover lists *.tf/*.tf.json per directory in a deterministic,
  depth-first walk; skips hidden dirs and the files Terraform ignores; never follows symlinked
  directories; records symlink_escape, symlinked_directory, not_regular, too_large and
  file_limit skips; skipped entries count toward the 10k limit; unreadable dirs fail closed.
- Files: internal/fsutil/{fsutil.go,open_unix.go,open_other.go,*_test.go},
  internal/terraform/{doc.go,discover.go,discover_test.go,discover_unix_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. Coverage: fsutil 91.4%, terraform 95.2%. Mutation checks:
  removing the IsRegular check or O_NONBLOCK makes the FIFO test fail. GOOS=windows/darwin
  `go vet` pass. Symlink and FIFO tests live in `//go:build unix` files.
- Review: iace-reviewer CHANGES_REQUIRED (1 major: an escaping symlinked directory left no trace;
  4 minor: unbounded skips, limit-boundary tests, unreadable-dir test, newline injection via
  paths). All fixed, then APPROVE with 2 minor (raw path inside *fs.PathError, a doc-comment
  wrap), both fixed. Follow-ups are recorded in BACKLOG: T-0102b resolves hidden-dir modules
  through fsutil; T-0109 turns every skip into a coverage gap.
- Next: T-0102b (separate root modules from local child modules).

## 2026-10-07 · T-0102b · done
- What: terraform.ClassifyModules splits discovered directories into roots and local children.
  It reads only module blocks, accepts only literal string sources (`./`, `../`) whose target is
  a directory inside the scan root (checked through fsutil, so hidden-dir modules are found and
  symlinks cannot escape), ignores self-calls, and promotes the first directory of an
  unreached call cycle to a root so nothing goes unscanned. New nesting guard: hcl v2.25.0
  crashes with an unrecoverable stack overflow on deep nesting (brackets, blocks, templates,
  for, unary operators, splat chains, conditional chains), so every file is checked on lexer
  tokens (HCL) or bytes (JSON) before parsing: at most 512 levels including open conditionals and
  unary runs, and 4,096 splats.
- Files: internal/terraform/{modules.go,modules_test.go,nesting.go,nesting_test.go}, go.mod,
  go.sum, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.5%. Crash thresholds were measured
  with probe programs outside the tree (300k levels crash for most kinds; ternary chains crash
  between 300k and 600k). Mutation check: without the literal-only check,
  `source = true ? "./a" : "./b"` is accepted and the test fails. New deps: hashicorp/hcl/v2
  v2.25.0 (MPL-2.0), zclconf/go-cty v1.19.0 (MIT), plus indirect MIT, Apache-2.0 and BSD
  modules. golang.org/x/text was raised to v0.42.0 because govulncheck flagged GO-2026-5970,
  reachable through hcl.
- Review: iace-reviewer CHANGES_REQUIRED (2 major: ternary chains passed the guard and crashed;
  `Value(nil)` evaluated operator chains and crashed. 3 minor). Both majors and the vacuous
  .tf.json test were fixed, then APPROVE (the reviewer's bypass probes passed). Follow-ups: T-0111
  (parse memory per file), a T-0104 bullet (bounded evaluation), a T-0107 bullet (children that
  no root instantiates).
- Next: T-0103 (parse HCL and JSON syntax files into raw blocks with ranges).

## 2026-10-07 · T-0103 · done
- What: terraform.ParseModule parses a directory's .tf and .tf.json files with hclparse. Files
  are read through fsutil with the size limit and pass the nesting guard first. It returns the
  top-level blocks (type, labels, file, full range from header to closing brace, body) in file
  order, plus sorted Diagnostics (severity, code, summary, file, line, column).
  - A file the parser rejects contributes no blocks.
  - Unknown top-level block types are warnings; top-level arguments are errors.
  - Override files are reported (`override_not_merged`) and checked for syntax and nesting, but
    not merged (ADR 0005).
  - Diagnostics keep only hcl's Summary, because its Detail can quote source values.
  - Terraform 1.14 `action` blocks are known.
- Files: internal/terraform/{parse.go,parse_test.go,fuzz_test.go,nesting.go},
  internal/terraform/testdata/fuzz/FuzzParseFile/*, docs/adr/0005-report-override-files-instead-of-merging-them.md,
  docs/security/threat-model.md (T14), docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.4%. FuzzParseFile: 15 seeds (12 inline,
  3 corpus files); 60s runs did 626,764 execs (first version) and 794,588 execs (final), with no
  failure. Mutation check: passing hcl's Detail through makes 5 leak cases fail.
- Review: iace-reviewer CHANGES_REQUIRED (2 major: hcl Detail leaked source values; nothing owned
  turning diagnostics into gaps. 3 minor: overrides not syntax-checked, missing `action` block, a
  misleading comment). All fixed, then APPROVE with 1 minor (owner for the ADR 0005 risk), fixed
  with T-0112 and threat-model entry T14. T-0109 now maps every diagnostic to a gap.
- Next: T-0104 (evaluate variables and locals).

## 2026-10-07 · T-0104a · done
- What: T-0104 was split into T-0104a (this: bound evaluation), T-0104b (variable values) and
  T-0104c (locals). (*ParsedModule).evalExpr is now the package's only path to Value. It checks
  the expression's own source first:
  - HCL tokens must pass the nesting limits and contain at most 1,000 binary operators.
  - In .tf.json, every string with `${` or `%{` (keys included) is lexed as a template and
    checked the same way, because hcl parses those only at evaluation time.
  - An expression whose source is not one of the module's files fails closed.
  - A rejected expression is unknown, plus an `expression_too_complex` warning at file:line.
  - Diagnostics are re-sorted and deduplicated after evaluation.
- Files: internal/terraform/{evalguard.go,evalguard_test.go,nesting.go,parse.go,fuzz_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.5%. A probe binary confirmed that a
  600k-operator chain inside a JSON template crashes when evaluated with a context, and that 1,000
  operators are fine. Mutation checks: disabling the guard fails 9 subtests, skipping the JSON
  check fails 7, and treating missing source as safe fails the fail-closed test. FuzzParseFile now
  evaluates every top-level attribute through evalExpr; a 60s run did 883,625 execs with no
  failure.
- Review: iace-reviewer CHANGES_REQUIRED (1 major: the fail-closed branches were untested; 3
  minor: sorted and deduplicated diagnostics, JSON nesting boundary tests, Variables() also parses
  JSON templates). All fixed, then APPROVE with 1 minor (dedup tie-breakers), fixed. Follow-ups:
  T-0104c (guard Variables() calls), T-0111 (index-chain memory), and a T-0109 mapping for
  expression_too_complex.
- Next: T-0104b (evaluate variable values).

## 2026-10-07 · T-0104b · done
- What: (*ParsedModule).EvaluateVariables evaluates a root module's variables in Terraform's
  precedence: default, terraform.tfvars, terraform.tfvars.json, *.auto.tfvars(.json) in lexical
  order (module directory only), --var-file in order, then --var in order.
  - Types come from typeexpr.TypeConstraintWithDefaults, so optional(T, default) defaults apply.
  - A value that does not convert is kept with a warning; an unset variable is unknown.
  - nullable = false replaces null with the default.
  - Sensitivity fails closed (anything but a clean false is sensitive), and sensitive values
    carry SensitiveMark.
  - As in Terraform, --var takes a primitive-typed or untyped value literally and parses complex
    types and explicit `any`.
  - Pipeline mistakes are errors: bad --var-file paths, malformed, undeclared or mistyped --var,
    and the argument is never echoed. Repository problems are diagnostics: undeclared names,
    tfvars syntax errors, references, duplicate declarations, more tfvars files than the limit.
  - Every value goes through evalExpr; .tf.json type strings are lexed as expressions before
    typeexpr parses them.
- Files: internal/terraform/{variables.go,variables_test.go,variables_internal_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.2%. Mutation checks: dropping
  defaults.Apply fails the optional-attribute test; starting sensitivity at false fails the
  fail-closed test.
- Review: iace-reviewer CHANGES_REQUIRED (2 major: optional(T, default) became a parse error and
  defaults were never applied; `sensitive = "true"` failed open. 6 minor: --var type mismatch,
  duplicate declarations, the argument echoed in an error, nullable, the tfvars file count and
  memory, untested path checks). All fixed, then APPROVE with 2 minor (a --var-file naming a
  module file dropped its source; a test at exactly the file limit), both fixed.
- Next: T-0104c (evaluate locals in dependency order).

## 2026-10-08 · T-0104c · done
- What: (*ParsedModule).EvaluateLocals evaluates a module's locals in dependency order.
  - The order comes from an iterative Tarjan SCC (no recursion; a 20k-local chain is fine). A
    local in a cycle (self-loops too) is unknown, with a local_cycle warning at its name.
  - Resources, data sources, ephemeral resources, modules, path and terraform evaluate as
    unknown, so known parts stay known. Their addresses become References (no instance keys),
    carried transitively through other locals.
  - Unknown lists the outermost unknown paths. Failed evaluation is unknown with an evaluation
    warning that quotes only hcl's summary. Duplicates keep the first (duplicate_local error).
  - Traversals are read only after safeToEvaluate. Diagnostics stay sorted and deduplicated.
  - Sensitivity fails closed: an unknown result, cycles included, keeps SensitiveMark when an
    input is sensitive.
  - Untrusted locals could double their values per local, so values are bounded:
    - Each local is checked before evaluation (source plus every use of a local or variable at
      full size) and after (size and nesting), against 2^18 units each and 2^22 in total.
      Over budget means unknown plus value_too_large.
    - References are capped at 2^17 entries in total. Past that, a local keeps only its own
      references and is ReferencesIncomplete; unanalysed and cyclic locals are too.
    - Unknown is capped at 1,024 paths and 4,096 steps, falling back to the whole value.
- Files: internal/terraform/{locals.go,locals_test.go,locals_internal_test.go,fuzz_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.8%; FuzzParseFile now runs
  EvaluateLocals, and a 30s run did about 400k execs with no failure. Limit tests run just below,
  at and just above every bound. Reviewer probes after the fix: tuple doubling over 60 locals in
  0.22s; a 20k-local reference chain uses 59 MiB of heap (it used 3.2 GiB before the fix).
  Mutation: dropping the cyclic sensitivity mark fails 3 assertions. A 20k-deep nested chain
  (670 KB) takes about 2s, linearly.
- Review: iace-reviewer CHANGES_REQUIRED (2 blockers: values doubling per local hung or OOMed
  the scan, and transitive references used quadratic memory; 3 minor: the error summary,
  unrecorded missing references, cancellation inside walks). All fixed, then APPROVE with 3
  minor:
  - the cyclic sensitive mark: fixed;
  - the per-use estimate charges whole values for attribute reads: T-0114;
  - for-expression cost in evalExpr, which predates this task and is not reachable from the CLI
    yet: T-0113, now a dependency of T-0109.
- Note: this iteration resumed work an interrupted session left uncommitted on the branch
  without marking the task [~].
- Next: T-0105 (curated function set).

## 2026-10-08 · T-0105a · done
- What: locals now evaluate with a curated, bounded function table.
  - T-0105 was split: T-0105a (this), T-0105b (Terraform's own pure functions) and T-0105c
    (file/fileexists/templatefile confined to the module).
  - Supported: 39 go-cty stdlib functions whose semantics match Terraform's, plus try/can.
    `core::name` aliases them. The table is documented in docs/reference/terraform-functions.md;
    a test checks that the doc matches the code, and every function has a case.
  - Every other called name is unknown, never an error, including provider:: functions, impure
    functions and undefined names. Each name gets one unsupported_function warning per module.
    Calls are found by walking the syntax tree (JSON templates are parsed after the token guard),
    and sensitive arguments keep the result sensitive.
  - Bounds: the wrapper takes untyped arguments, sizes them (valueSize now counts a number's
    decimal digits, magnitude plus 512-bit mantissa) before converting them as hcl would, and
    applies the per-call argument and result limits (2^18 units, maxNesting), a format/formatlist
    output bound, and a per-module work budget (2^23 units, about 1.5s worst case). Over any
    bound, the call is unknown and keeps its sensitivity, and the expression gets a function_limit
    warning.
  - Variables and tfvars still evaluate without functions, as in Terraform.
- Files: internal/terraform/{functions.go,functions_internal_test.go,evalguard.go,locals.go,
  parse.go,locals_test.go,fuzz_test.go}, docs/reference/terraform-functions.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.6%. Tests sit below, at and above
  every bound. Mutation checks (dropping the format cost, the result check, the sensitive mark
  on a limit, the once-per-name dedupe, or MinPrec in numberDigits) each fail a test.
  FuzzParseFile ran 45s (about 800k execs) with new function seeds and found nothing. Probes:
  - tostring(1e6000000), join or format over 1e2000000, and toset over colliding numbers took
    24 ms in total (the reviewer measured 10–20s and minutes before the fix).
  - 3,000 locals of heavy calls stop at the module budget.
  - 24,000 high-precision fractions with 100 contains/jsonencode locals: 13 ms.
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED.
    - 2 blockers. distinct does quadratic work on costly number comparisons. cty sets degrade to
      comparing every pair when number hashes collide.
    - 1 major: numbers counted 1 unit whatever their size, and hcl converted arguments before
      the wrapper ran.
    - 4 minor: lookup's semantics differ from Terraform's, the lexer reported in/if as
      functions, T-0109 did not map the new diagnostics, and some at-bound tests were missing.
    - All fixed: distinct, toset, setunion, setintersection, setsubtract and lookup moved to
      T-0105b; numbers are sized by their digits; the wrapper converts arguments itself; calls
      are found with VisitAll; T-0109 updated.
  - Round 2: CHANGES_REQUIRED, 1 blocker: number size ignored mantissa precision. Fixed.
  - Round 3: APPROVE.
- Note: the function table in the harness reference
  (.claude/skills/iace-terraform-parsing/references/hcl-evaluation.md) lists functions that now
  sit in T-0105b/c or stay unknown, and a 1 MiB string cap where the code uses 2^18 units. The
  repo doc is authoritative for what is implemented. The owner may want to sync the skill text.
- Next: T-0105b (Terraform-specific pure functions).

## 2026-10-08 · T-0105b · done
- What: Terraform's linear pure functions, implemented in iace.
  - T-0105b was split first. This slice holds the linear functions; replace, regex and
    regexall moved to T-0105d, cidr* to T-0105e, and distinct and the set functions to T-0105f.
  - New in internal/terraform/functions_terraform.go, each written from Terraform's docs (never
    its BUSL-1.1 source):
    - length: graphemes; tuple and object length known from the type.
    - coalesce: skips null and "", unifies the argument types.
    - index: unknown before a match makes the result unknown.
    - lookup: optional, nullable default; objects and maps; unknown unless the map is wholly
      known, as in Terraform.
    - startswith, endswith, strcontains.
    - base64encode and base64decode: decoding checks UTF-8.
  - All are in the bounded table.
  - contains and index charge the product of their argument sizes when a set can be involved,
    because cty compares sets pairwise when number hashes collide.
  - valueSize no longer panics on unknown or marked set elements.
  - The reference doc gains a semantics table. It states that iace marks results more broadly
    than Terraform (nested marks included), which fails closed.
- Files: internal/terraform/{functions_terraform.go,functions_terraform_internal_test.go,
  functions.go,functions_internal_test.go,locals.go}, docs/reference/terraform-functions.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.4%. Every function has a
  case, and the 49 error, unknown and edge cases pass. Mutation checks each fail a test:
  coalesce keeping "", lookup ignoring partially known maps, index dropping marks or skipping
  unknown comparisons, no UTF-8 check, length counting bytes, no set comparison charge. A
  colliding-set index/contains call is limited in well under 2s.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - 1 major: index and contains over sets with colliding hashes cost seconds per call.
    - 4 minor: index lost sensitivity on unknown arguments; index on a dynamic list gave a
      dynamic value; over-marking was undocumented; no length-on-set test.
    - Also flagged: valueSize panicked on sets with unknown elements (pre-existing).
    - All fixed.
  - Round 2: APPROVE, with 2 minor doc findings, both fixed. T-0116 was widened to all
    unification and conversion into set types (HCL conditionals included), and the reference's
    worst-case note now names that exception.
- CI round 1 (attempt 2): red. TestSetComparisonsAreCharged had a 2s wall-clock assertion,
  and under -race in CI the limited call took 2.7s, because iterating a set of colliding numbers
  sorts it at a cost per comparison. The test now asserts only the outcome (unknown with
  function_limit), which fails without the charge.
- Next: T-0105c (file functions confined to the module directory).

## 2026-10-08 · T-0105c · done
- What: file(), fileexists() and templatefile(), confined to the module directory.
  - fsutil gains Root.OpenRoot. Each call opens a sub-root of the module directory, so neither
    `..` nor a symlink can leave it, even to a file elsewhere in the repository. Empty,
    absolute, `\`, `~` and drive-letter paths are refused before any I/O.
  - Relative paths resolve against the module directory, and path.module is ".". path.root and
    path.cwd stay unknown. T-0107 will rebase paths for child module instances.
  - Problems are unknown with a warning, never an error, emitted at the calling expression:
    - file_outside_module, for a refused path;
    - file_unreadable: missing, over 1 MiB, not a regular file, not UTF-8, or a symlink escape;
    - template_error, at the template file: syntax, unknown variable, var.*, or a nested
      templatefile.
  - Templates pass the nesting and operator guard and use the module's bounded function table.
  - Bounds: each call charges 1 KiB before touching the filesystem, reads are capped at the
    remaining work (a larger file is refused by size, unread), and every byte read is charged.
- Files: internal/fsutil/{fsutil.go,fsutil_unix_test.go}, internal/terraform/{functions_files.go,
  functions_files_internal_test.go,functions_files_unix_test.go,functions.go,evalguard.go,
  parse.go,locals.go,locals_test.go,functions_internal_test.go}, docs/reference/terraform-functions.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 97.0%. 32 file-function cases plus
  symlink-escape, sensitivity, size-boundary and budget tests. Mutation checks each fail a
  test: reading via the scan root instead of the sub-root, no UTF-8 check, nested templatefile
  allowed, no `..` check, no read charge, no read cap, charging after the UTF-8 check.
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED, 1 major and 4 minor.
    - Major: once the budget was below a file's size, reads kept happening without a charge
      (about 130k 1 MiB reads per module).
    - Minor: fileexists was uncharged; T-0109 did not map the new codes; the root lifetime was
      undocumented; a dead null branch.
    - All fixed, and the fidelity differences were documented.
  - Round 2: CHANGES_REQUIRED, 1 major: a non-UTF-8 file was read without being charged. Fixed by
    charging before the UTF-8 check.
  - Round 3: APPROVE.
- Next: T-0105d (replace, regex and regexall with bounded regular expressions).

## 2026-10-08 · T-0105d · done
- What: replace (plain and /regex/), regex and regexall, with every cost bounded before it is
  paid.
  - All three are iace module functions; regex and regexall return go-cty's result shapes
    (string, tuple of unnamed groups, object of named groups, null for unmatched groups).
  - Patterns:
    - at most 4 KiB;
    - charged 64 units per byte plus one per class rune, and parsed once per module (cache of
      256; past it, one slot shared by a call's type check and run);
    - a parse-tree estimate that never undercounts Go's program refuses anything over 8,192
      before compiling; the compiled program must be ≤ 4,096 instructions.
  - Matching: each search is charged size × (groups+1) × (len+1). Find-all stops at the
    matches the remaining work affords (2k+1 searches for k matches) and at what a result
    holds; otherwise the call is unknown.
  - replace checks its output size before building it: exactly for a plain substring, from the
    matches and `$` count for a regex. It builds from the matches, equal to Go's
    ReplaceAllString.
  - The bounded wrapper:
    - spends work on refused calls;
    - treats an unknown result whose type does not match the declared one as limited.
- Files: internal/terraform/{functions_regex.go,functions_regex_internal_test.go,race_on_test.go,
  race_off_test.go,functions.go,functions_files.go,parse.go,functions_internal_test.go},
  docs/reference/terraform-functions.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 96.6%.
  - Tests: per-function semantics, a differential test against ReplaceAllString (784 cases),
    estimate ≥ compiled size on 26 patterns, exact budget boundaries, allocation tests
    (oversized replace and compile refusals), a retained-heap test for the cache, and a
    budget sweep for can().
  - Mutation checks each fail a test: no estimate gate, unscaled per-search charge, no
    compiled-size check, no pattern cap, no cache cap, kept parse trees, no rune charge, no
    one-slot reuse, no regex replace charge, no `$` term, no plain bound.
- Review: iace-reviewer, 4 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blockers: find-all is quadratic (`x*y|x` over 40k took 23–46s), and go-cty compiled
      patterns in Type before the cost check, with refused calls free.
    - Major: the estimate was up to 2× low.
    - Fixed by the redesign above.
  - Round 2: major: unbounded cache memory with Unicode classes (252 MiB in one module). Fixed
    with the 256-entry cache, dropped parse trees and the rune charge.
  - Round 3: major: past the cache, Type and Impl could disagree near the budget's end, so
    can() gave a wrong known false. Fixed with the one-slot reuse and the conformance check.
  - Round 4: APPROVE. Note: a non-conforming known result in bounded is an error, which can()
    reads as false; only a future bug could reach it.
- Next: T-0105e (cidrsubnet, cidrhost, cidrnetmask).

## 2026-10-08 · T-0105e · done
- What: cidrsubnet, cidrhost and cidrnetmask, written from Terraform's docs with net/netip and
  math/big, in the bounded table.
  - Prefixes are parsed strictly: leading zeros, zones and IPv4-mapped prefixes are errors.
    Host bits are dropped.
  - Numbers must be whole. newbits is between 0 and min(32, free bits), and netnum fits newbits.
    A negative hostnum counts back from the end. cidrnetmask is IPv4 only.
  - A result in IPv4-mapped IPv6 space is unknown: Terraform prints it as IPv4 text
    (cidrsubnet("::/80", 16, 65535) is "0.0.0.0/0" there), so a known different value would let
    an open ingress rule pass.
  - Error messages never quote the arguments, which may be sensitive or huge.
- Files: internal/terraform/{functions_network.go,functions_network_internal_test.go,functions.go,
  functions_internal_test.go}, docs/reference/terraform-functions.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; terraform coverage 96.7%. 50 cases cover every error
  branch, the /0, /31, /32 and IPv6 boundaries, unknown and sensitive arguments, and Terraform's
  documented IPv6 example. Mutation checks each fail a test: negative netnum accepted, host bits
  kept, IPv4-mapped prefixes accepted, hostnum below range accepted.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: IPv4-mapped results differed from Terraform's text, an evasion path.
    - Minor: arguments quoted in errors; stale comments; untested boundaries.
    - All fixed. newbits > 32 is now unknown (fail closed).
  - Round 2: APPROVE, with a minor fix to a test comment, applied.
- Note: the newbits limit of 32 follows Terraform's documented behavior; it could not be checked
  against current Terraform source offline. It fails closed either way.
- Next: T-0105f (distinct and the set functions with a collision-proof cost bound).

## 2026-10-08 · T-0105f · done
- What: distinct, toset, setunion, setintersection and setsubtract (go-cty stdlib, as Terraform
  uses them) in the bounded table.
  - `bounded` takes a `before` cost, checked after measuring the arguments and before converting
    them: converting a list to a set builds the set. The type pass charges it too, because it
    converts as well and cty skips the call when an argument is unknown. A refusal there is
    reported as function_limit.
  - setBuildCost: elements of all arguments × their total comparison weight, or weight² when
    elements can hold sets (comparing sets is pairwise in turn).
  - Comparison weight = size + (fractional bits / 32 + 1)² per non-integer number. Found during the
    task: cty compares such numbers by exact decimal text, and math/big's expansion is quadratic in
    the fractional bits (one comparison of 1e-78000 took 1.9s at 78k units).
  - Sets of compound elements are refused when a number has over 1,024 fractional bits: cty orders
    them by hash, so every later use formats the numbers again.
- Files: internal/terraform/{functions.go,functions_internal_test.go},
  docs/reference/terraform-functions.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. The 1,024-colliding-number regression (all five functions)
  is refused before any work; it took 20s before. A timing sweep over colliding numbers, tuple and
  object elements, unknown-argument loops and 1e-300…1e-6000 measured at most about 120ns per
  charged unit (the reviewer measured 67ns), so a full budget is about 1s. Mutation checks each fail a
  test: no set charge, type pass ignoring the budget, type pass not charged, type refusal free or
  unreported, no format cost, nested not squared, pre not charged, counting arguments instead
  of elements, no compound cap.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: the type pass built sets uncharged, and with an unknown argument cty never calls
      Impl (10 calls: 3.3s for 504 units). Fixed by charging the type pass.
    - Major: compound sets of tiny numbers re-hash on every later use (58s). Fixed by the cap.
    - Minor: the calibration was optimistic for setunion (up to 250ns per unit). Fixed with root 32
      and a re-run sweep.
  - Round 2: APPROVE. Minor: other functions' type-pass conversions of numbers (`join`) are
    uncharged when an argument is unknown. This predates the task and was added to T-0117.
- Next: T-0106 (count, for_each and dynamic blocks).

## 2026-10-08 · T-0106a · done
- What: T-0106 split into T-0106a–d. No schema-less resource decoding existed, and count/for_each,
  dynamic blocks and JSON bodies each need their own slice. This slice adds
  `ParsedModule.DecodeResources(ctx, vars, locals)`, which turns each HCL `resource` and `data`
  block into one `Resource`:
  - address, mode, type, name, file and ranges;
  - a value object of the evaluated attributes, with nested blocks as tuples of objects in source
    order;
  - unknown paths, sensitive marks, and attribute ranges keyed by dot-joined path.
  - Evaluation context: `var`, the referenced locals, and `path` (`pathObject`, now shared with
    locals). Resources, data sources, modules, `count`, `each`, `self` and `terraform` are
    unknown. `terraform.workspace` stays unknown, consistent with locals (the parsing skill
    suggests "default", but a CI workspace can be anything).
  - Meta-arguments only at the top level:
    - raw `count`/`for_each` kept for T-0106b;
    - `provider` → "aws.eu";
    - `depends_on` → sorted addresses;
    - `lifecycle` → prevent_destroy (converted to bool) and ignore_changes (dot paths, `all` → `*`);
    - `provisioner` and `connection` skipped.
    Invalid meta-arguments are ignored with an `evaluation` warning.
  - Fail closed:
    - a `dynamic` block makes its type unknown (`dynamic_block_not_expanded`);
    - a `.tf.json` body is wholly unknown (`json_body_not_decoded`);
    - an attribute/block name clash is unknown;
    - an evaluation error is unknown, and stays sensitive when an input is.
  - Size: a pre-evaluation estimate and a post-evaluation measure, with maxLocalValueSize per
    attribute and 2^22 per module (`value_too_large`). Size and sensitivity of each var and local
    are cached, so references cost lookups. Ephemeral resources are not decoded.
- Files: internal/terraform/{resources.go,resources_test.go,locals.go,fuzz_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. FuzzParseFile now also decodes resources (60s, about 770k
  inputs, clean). Mutation checks each fail a test:
  - no module budget, no estimate, no sensitivity cache;
  - meta-arguments also in nested blocks;
  - dynamic not unknown, a clash keeping the block, an unknown losing sensitivity.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: ContainsMarked ran per reference, uncached, so 2,000 references to an 800 KB
      variable took 93s. Fixed with the cache, and a test bounding allocation (without the
      cache: 86s and 72 GB). Profiling then showed the linear walk at 2^24 units took about 4s,
      so the module budget is now 2^22.
    - Minors: `provider = aws["eu"]` silently lost the alias (now invalid); prevent_destroy did
      not convert "true" (now converted); the too-complex path's unmarked unknown is now
      documented; T-0106d now depends on T-0106c; T-0109 now maps the two new codes.
  - Round 2: APPROVE. Its minor finding (check the conversion error instead of comparing with
    NilVal) was applied, and the gates re-ran.
- Next: T-0106b (count and for_each).

## 2026-10-08 · T-0106b · done
- What: DecodeResources now expands count and for_each.
  - Meta-arguments are recorded once per block. The body is decoded once per instance, with
    `count`/`each` bound; their sizes and sensitivity are measured once per instance.
  - count: converted to a number. A sensitive count expands as Terraform allows, with plain
    indexes. Unknown gives a `[*]` placeholder with count_unknown (unknown_expansion). Null,
    negative, fractional or non-numeric gives the placeholder with invalid_expansion.
  - for_each:
    - a map or object, where each.value is the element (sensitive element values flow
      through);
    - a set of strings, where each.value is the key;
    - sensitive keys, null, a list or a non-string set → invalid;
    - unknown → placeholder;
    - both count and for_each → placeholder with both flags.
  - Keys are sorted and quoted with hclwrite (`$${`, `%%{`, `\u0007`), as Terraform writes
    addresses.
  - Caps, each reported per truncated resource (expansion_limit):
    - 10,000 instances per resource;
    - 100,000 per module;
    - maxInstanceStructure 2^27 estimated bytes (instance 1024, attribute 256, block 768);
    - maxExpansionWork 2^21 bytes of re-evaluated source (measured 200–630 ns/byte, so about
      1s at worst).
- Files: internal/terraform/{resources.go,resources_expand.go,resources_expand_test.go,
  resources_expand_internal_test.go,resources_test.go,fuzz_test.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; fuzzing 45s, clean.
  - TestExpansionHeap, live heap at the module limits:
    - bare: 100,000 instances, 66 MB;
    - 20 attributes: 20,971 instances, 115 MB;
    - 20 blocks: 8,065 instances, 32 MB;
    - nested blocks: 37,449 instances, 104 MB.
  - Value-heavy shapes can add about 206 MB more (T-0118).
  - Mutation checks each fail a test: each cap removed, sensitive count rejected, a number set
    accepted, negative/fractional accepted, each-sensitivity lost.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: a sensitive count was wrongly invalid. Terraform allows it; fixed.
    - Major: per-instance structure was uncharged (a 1.2 KB file held 273 MB). Fixed with the
      structure budget and the heap test.
    - Minors, all fixed: strconv quoting differed from Terraform's; later resources were cut
      without a warning; there was no exact work-bound test.
  - Round 2: APPROVE, with two minors.
    - Re-evaluation measured up to 630 ns/byte, so maxExpansionWork was lowered to 2^21.
    - Value-heavy memory is now follow-up T-0118, which also covers dynamic blocks in
      instanceStructure.
  - T-0113 now names resource instances as an amplifier.
- Next: T-0106c (dynamic blocks).

## 2026-10-08 · T-0106c · done
- What: dynamic blocks expand during resource decoding, following hcl's ext/dynblock (which
  Terraform uses).
  - Entries merge with static blocks of the same type in source order.
  - The iterator, named by `iterator` or else the label, is {key, value}: an index for a list
    or tuple, a key for a map or object, the element for a set.
  - The iterator shadows any root of its name, `var`/`local`/`path` included. Nested dynamics
    see outer iterators, which are restored afterwards.
  - A sensitive for_each marks the entries. Content attribute ranges are recorded under the
    entry paths.
  - Unknown for_each, or a set that is not wholly known: one entry with an unknown iterator,
    and the type path is added to Unknown (mergeUnknown keeps only outermost paths, in value
    order); unknown_expansion.
  - Invalid forms make the type unknown (invalid_expansion): no single label, a dynamic
    lifecycle/provisioner/connection, no for_each, a stray argument or block, not exactly one
    unlabelled content block, a bad iterator, or a for_each that is null or not a collection.
  - Limits: 10,000 entries per block. Every entry charges the module structure budget, and
    each after the first charges the re-evaluation work. A block cut short is expansion_limit,
    with its type unknown. No entries leave the type absent.
  - DiagDynamicBlockNotExpanded is removed.
- Files: internal/terraform/{resources_dynamic.go,resources_dynamic_test.go,
  resources_dynamic_internal_test.go,resources.go,resources_test.go,fuzz_test.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. FuzzParseFile with a dynamic seed, 45s, clean.
  - Mutation checks each fail a test: no per-block cap, no structure check, no work check,
    unknown path not marked, marks dropped, iterator not restored, a partial set treated as
    known, iterators not shadowing var/local/path.
  - Reviewer probes: 100 instances × 1000 × 1000 nested entries stopped at the structure limit
    in 1.1s with 126 MB live; 16 levels deep took 0.65s with 60 MB.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major (fail-open): an iterator named local/var/path did not shadow those roots, so iace
      checked a value Terraform does not apply. Fixed; the regression test reproduces it when
      the fix is reverted.
    - Minors, both fixed: no at-the-limit entry test; dynamic forms that hcl rejects were
      accepted.
  - Round 2: APPROVE, no findings.
- Next: T-0106d (.tf.json resource bodies, with an ADR on the block-vs-map heuristic).

## 2026-10-08 · T-0106d · done
- What: resource and data bodies in `.tf.json` decode like HCL bodies.
  - DecodeResources works through a `resourceBody` interface (HCL and JSON implementations of
    metaArguments, cost, structure and decode).
  - JSON bodies read `lifecycle`, `provisioner`, `connection` and `dynamic` as blocks
    (PartialContent), and every other property as an attribute (JustAttributes, sorted by
    source). A body Terraform would reject is wholly unknown with a warning.
  - ADR 0006 (amends ADR 0004 rule 1): JSON properties keep their written shape, so a nested
    block written as one object stays an object, and so do its unknown and sensitive paths.
    The iace.lib.tf path helpers resolve index 0 against an object, and `tf.blocks` is required
    for iteration.
  - T-0201 gains the helpers and a lint, and T-0205 requires a `.tf.json` fail fixture for every
    rule. The schema description and model comment note the exception, and T-0110 now covers
    ADR 0006.
  - Meta-arguments work as in HCL. A second lifecycle block is now ignored with a warning in
    both syntaxes (HCL used to apply every one), and so is a JSON lifecycle that is not an
    object.
  - JSON `dynamic` blocks, at the top or inside a nested block object (any value holding a
    "dynamic" key with an object or array), are unknown with json_dynamic_not_expanded, once
    per resource, until T-0106e. The detection walk is linear.
- Files: internal/terraform/{resources_json.go,resources_json_test.go,
  resources_json_internal_test.go,resources.go,resources_test.go,fuzz_test.go},
  internal/model/input.go, schemas/input.v1.json, docs/adr/0006-decode-json-resource-bodies-as-written.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; JSON fuzz seed, 45s, clean. Mutation checks each fail a
  test:
  - JSON meta-arguments in values, lifecycle ignored, dynamic not unknown;
  - duplicate lifecycle accepted, PartialContent errors ignored;
  - nested dynamic kept, nested dynamic losing sensitivity, a string "dynamic" treated as a
    block;
  - JSON lifecycle error ignored, UnmarkDeep in the walk (3.2M allocations for 2,300 values).
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: a nested JSON dynamic was silent data.
    - Major: the ADR missed the unknown-path shape, and the false-positive and misjudged-unknown
      modes (the seed EC2 rule indexes [0]).
    - Major: the schema/contract text and T-0110 were not updated.
    - Minors: a JSON lifecycle that is not an object was silent; the dynamic warning fired per
      instance.
    - All fixed.
  - Round 2: CHANGES_REQUIRED.
    - Major (DoS): the dynamic-key walk used UnmarkDeep per node, nodes × depth, 91s. Fixed with
      a shallow Unmark and an allocation-bounded test.
    - Minor: the lint and guide now also cover `[_]` and `some … in` iteration.
  - Round 3: APPROVE, no findings.
- Next: T-0106e (dynamic blocks in JSON).

## 2026-10-08 · T-0106e · done
- What: dynamic blocks written in JSON expand like HCL ones.
  - The HCL dynamic() validates its block and hands a dynamicSpec to a syntax-neutral
    expandDynamic(). That core holds the iterator binding, shadowing and restore, the marks,
    unknown/null/non-collection handling, the per-block cap, and the module structure and work
    charges.
  - jsonDynamic reads a dynamic block with hcl's schema decoding (for_each, iterator, labels,
    content).
  - jsonBody, parsed with the resource or nested schema, decodes bodies recursively.
  - A property whose source holds a dynamic block (a structural ExprMap/ExprList walk, memoized
    by source range so nesting stays linear), or that shares a dynamic type, decodes as an array
    of blocks through hcl's JSON block decoding. Its entries record ranges.
  - Static and dynamic entries merge in source order (ADR 0007 amends ADR 0006; T-0110 now
    covers it).
  - JSON re-evaluation is charged at jsonEvalFactor 4 per byte, because each evaluation
    re-parses the string templates (measured about 1.7µs per byte). Each dynamic block is charged
    from its "dynamic" key to its closing brace; its DefRange is only the opening brace.
  - json_dynamic_not_expanded is removed. Duplicate "dynamic" keys expand.
- Files: internal/terraform/{resources_json.go,resources_dynamic.go,resources.go,
  resources_json_dynamic_test.go,resources_json_test.go,resources_json_internal_test.go},
  docs/adr/0007-decode-json-properties-holding-dynamic-blocks-as-blocks.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass; fuzzing 45s, clean.
  - Mutation checks each fail a test:
    - static entries not merged, nested dynamic kept as data, a dynamic lifecycle accepted;
    - JSON entries costing nothing, two contents accepted, dynamic source not charged (33s and
      a failure);
    - no JSON factor, source order ignored, no memo (771 MB against 40 MB).
  - The reviewer's worst case (2.4 MB at depth 400) dropped from 111s to 1.9s.
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: a JSON dynamic cost 1 byte, so count × dynamic took 74s.
    - Major: detection evaluated out of iterator scope, and double-charged values.
    - Major: no ADR amending 0006.
    - Minor: static-first ordering.
    - All fixed.
  - Round 2: CHANGES_REQUIRED.
    - Blocker: the structural walk was depth × size. Memoized.
    - Minor: the full-body JustAttributes failed on duplicate block keys. Each block is now
      measured from its own ranges.
  - Round 3: APPROVE. Minor (memoizing scalar leaves costs memory) is recorded in T-0111.
- Next: T-0107 (resolve local and pre-downloaded modules).

## 2026-10-09 · T-0107a · done
- What: the module call tree of a root module.
  - T-0107 was split into T-0107a–f: the call tree, inputs and outputs, count/for_each on calls,
    modules.json, uninstantiated children, and child paths. T-0108 and T-0112 now depend on the
    later slices, and T-0109 maps module_unresolved, ModuleTree.Skipped and Truncated to gaps.
  - LoadModuleTree walks the module blocks depth first in block order. Each call keeps its
    address, literal source and version, file and ranges. Nothing is evaluated.
  - Local sources resolve inside the scan root. Every path component is Lstat'ed through the
    root (new fsutil.Root.Lstat), so no symlink is followed, as in discovery.
  - Unresolved calls stay in the tree with a reason (remote_source, source_not_literal,
    missing_source, outside_root, not_found, symlinked_directory, depth_limit, cycle,
    call_limit) and a module_unresolved warning. Duplicate and invalid names are errors.
  - Each directory is parsed and its blocks analyzed once. Hidden directories are listed within
    discovery's MaxFiles budget (Discovery.Entries).
  - A tree holds at most 1,000 calls, resolved or not. Past that, the walk stops and Truncated
    is set (ADR 0008, threat model T3).
  - go.mod toolchain go1.27.1 → go1.27.2: govulncheck flagged GO-2026-6604 (os.Root, Windows),
    which failed the vuln gate on main as well.
- Files: internal/terraform/{modules_tree.go,modules_tree_test.go,modules_tree_unix_test.go,
  modules.go,discover.go,discover_test.go,discover_unix_test.go},
  internal/fsutil/{fsutil.go,fsutil_test.go,fsutil_unix_test.go},
  docs/adr/0008-bound-the-module-call-tree.md, docs/security/threat-model.md,
  docs/plan/BACKLOG.md, go.mod
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test: no Entries seed, no listFull guard, no call-limit check,
    no symlink check.
  - The reviewer's attack (1,000 calls to a 4.99 MB module of 150k source-less blocks) went
    from 60s and 13.8 GiB (on a 370 KB file) to 3.0s and 382 MiB.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: only resolved calls were bounded, so instances × unresolved blocks grew without
      limit (DoS).
    - Minors: symlinked directories defeated cycle detection and the parse cache; listing had a
      second file budget and repeated file_limit skips; no ADR for the limits.
    - All fixed.
  - Round 2: APPROVE, no findings.
- Note: an attempted change to treat JSON sources holding `${` as non-literal was reverted.
  Terraform decodes module sources without a context, so they are literal strings
  (TestModuleSourcesNeverEvaluates).
- Next: T-0107b (flow module inputs and outputs).

## 2026-10-09 · T-0107b · done
- What: module inputs become a child module's variables.
  - The old T-0107b was split into T-0107b (inputs), T-0107g (evaluate the tree within a
    tree-wide budget) and T-0107h (outputs as `module.x.y`). T-0107c and T-0107f were re-pointed.
  - ParsedModule.ModuleInputs evaluates a call's arguments in the caller with var and local,
    through the resource decoder's evalBounded (per-value and per-call size limits).
    newResourceDecoder was factored out of DecodeResources.
    - source, version, count, for_each, providers and depends_on are skipped.
    - A nested block is an HCL error.
    - Module, resource and other references are unknown.
  - EvaluateModuleVariables shares declareVariables with EvaluateVariables.
    - Inputs replace defaults.
    - An undeclared input is an error (undeclared_module_input), and a missing required input
      is an error and unknown (missing_module_input). Both are reported in the caller's file.
  - finishVariable unmarks deeply before conversion and marks the whole converted value when
    anything was sensitive (fail closed).
  - NewInstance shares the parse's blocks and gives each instance its own diagnostics, function
    table and work, file reads, regex cache and source map.
- Files: internal/terraform/{modules_inputs.go,modules_inputs_test.go,
  modules_inputs_internal_test.go,variables.go,resources.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test: no meta-argument filter, NewInstance returning the parse,
    no missing-input check, no re-marking after conversion.
  - The first size test used a 1024×1024 nested `for` and took 15.5s, which is the known
    T-0113 gap. It was replaced by a large variable default.
- Review: iace-reviewer, APPROVE with three minors.
  - The shared src map was written by EvaluateVariables: fixed with maps.Clone per instance,
    and tested.
  - Size edges, the per-call total and cancellation were untested: tests added.
  - A null value for a non-nullable variable without a default is accepted silently (also in
    EvaluateVariables): follow-up T-0119.
- Next: T-0107g (evaluate the module tree).

## 2026-10-09 · T-0107g · done
- What: a module tree is evaluated, within tree-wide budgets.
  - EvaluateTree evaluates the root (EvaluateVariables) and every resolved call depth first,
    each in its own NewInstance: ModuleInputs in the caller, then EvaluateModuleVariables,
    EvaluateLocals and DecodeResources.
  - Resources get Module, CallFile and CallRange, and module-prefixed Address and BaseAddress.
  - Tree budgets (ADR 0009) are charged after each instance, and after each call's inputs on
    the caller. An instance runs only while every budget has some left, so each kind stays
    within two modules' worth.
    - 8 MiB of child source; the root is not charged.
    - One module's function work, locals, resources, inputs, local reference entries,
      expansion work, structure and instances.
    - 2^20 steps of unknown paths.
  - Instances past a budget are Skipped, with module_work_limit at the call. The inputs of one
    caller's calls share one value budget.
  - T-0108 gains a bullet for qualifying references and depends_on inside modules. T-0109 maps
    module_work_limit. T-0118 gains the per-module unknown-path weight. Threat model T3
    references ADR 0009.
- Files: internal/terraform/{modules_eval.go,modules_eval_test.go,modules_eval_internal_test.go,
  modules_inputs.go,locals.go,resources.go,parse.go},
  docs/adr/0009-bound-the-evaluation-work-of-a-module-tree.md, docs/security/threat-model.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - A fan-out of 1,000 heavy calls stops after about 42 instances (source) or 2 (function
    work), in under a second. 1,000 small instances are all evaluated.
  - Mutation checks each fail a test: no budget check, no source charge, no caller charge, no
    locals usage, no shared inputs, no address prefix, no refs or unknown dimension, no
    unknown recording.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: local reference entries were not charged (51.7M entries, 913 MiB live).
    - Major: one combined value budget gave locals four modules' worth, and unknown paths were
      not counted (2.3 GiB live).
    - Minors: the ADR's worst-case claim, and the root charged to the source budget.
    - All fixed with per-kind budgets, refs and unknown dimensions, and regression tests built
      from the probes.
  - Round 2: APPROVE. The probes now run at 8 MiB and 387 MiB live; the 387 MiB is one module,
    tracked in T-0118. The minor about the usage doc for accumulating unknown steps is fixed.
- Next: T-0107h (expose module outputs to callers).

## 2026-10-09 · T-0107h · done
- What: module outputs reach their callers' resources and outputs.
  - T-0107h was split into h (resources and outputs) and i (locals and module inputs, with one
    dependency order and cycles). T-0107c now depends on T-0107i.
  - evaluateOutputs evaluates output blocks through evalBounded, in their own value budget.
    - `sensitive` is evaluated fail-closed and marks the value.
    - A missing value gives missing_output_value and a duplicate gives duplicate_output; both
      are errors.
    - Unknown steps are charged.
  - resourceDecoder.modules gives resources and outputs `module.<name>`: an object of the
    call's outputs, or unknown when the call is unresolved, skipped or truncated. A name that
    is not called is an evaluation warning, and its value is unknown. With nil modules
    (DecodeResources, ModuleInputs) the module is unknown as before.
  - EvaluateTree runs variables, locals, calls, then resources and outputs. A child whose calls
    used up the tree budget is Truncated: its resources and outputs are not evaluated, and it
    gets module_work_limit at its call. The root is exempt (ADR 0010, extending 0009). Outputs
    are a tree budget dimension.
- Files: internal/terraform/{modules_outputs.go,modules_outputs_test.go,modules_eval.go,
  modules_eval_internal_test.go,resources.go},
  docs/adr/0010-evaluate-module-calls-before-resources-and-outputs.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test:
    - modules not passed to resources, no sensitive mark, always or never sensitive;
    - skipped or truncated outputs used, no outputs usage, no module sensitivity;
    - no truncation, no truncation warning.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: with calls before resources, every ancestor on a call chain decoded its
      resources after the tree budget was gone (a chain of 30 used 29 times the budget).
      Fixed by truncating such ancestors, with the probe as a regression test.
    - Minors: untested `sensitive = false` and non-constant `sensitive`; an in-place edit of
      ADR 0009, reverted in favour of ADR 0010. Both fixed.
  - Round 2: APPROVE. Its minor, that the truncation warning and the truncated-output
    unknowns were untested, is now covered by assertions; the two mutations fail.
- Next: T-0107i (order locals and module calls by their dependencies).

## 2026-10-09 · T-0107i · done
- What: locals and module calls are evaluated in one dependency order.
  - evaluateLocals builds one graph: locals keyed by name, calls keyed by `module.<name>`. Edges
    come from local and module references in locals, and in each call's arguments
    (callDependencies).
  - dependencyComponents (Tarjan, explicit stack) replaces localsInDependencyOrder and returns
    whole components. A call is evaluated through a callback with the locals and module values
    evaluated so far.
  - Locals, module inputs (moduleInputs), resources and outputs see `module.<name>` for the
    module's own calls. Another name is an evaluation warning and unknown.
  - Cycles: all members are unknown. Locals get local_cycle and calls get module_cycle. Calls in
    a cycle get their placeholders first, are still evaluated (their resources are checked),
    and their outputs stay unknown.
  - A child instance charges and checks the tree budget before each local. Once a budget is used
    up, its remaining locals are unknown and it is truncated (ADR 0010). The root never stops
    (ADR 0011).
- Files: internal/terraform/{locals.go,modules_eval.go,modules_inputs.go,modules_order_test.go,
  modules_eval_internal_test.go}, docs/adr/0011-order-locals-and-module-calls-together.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test: no stop, stop at the root, cyclic outputs kept, no module
    object in locals, no call dependencies, no module sensitivity in locals.
  - Without stop, a chain of 30 modules with locals after their calls used 232M units of
    function work against an 8.4M budget.
- Review: iace-reviewer, APPROVE with five minors, all fixed:
  - the exact instance order is now asserted;
  - the EvaluateTree doc comment is corrected;
  - call placeholders are set before a cycle's locals;
  - the truncation warning and the root's locals are asserted;
  - a cycle of two calls is tested.
- Next: T-0107c (count and for_each on module calls).

## 2026-10-09 · T-0107c · done
- What: module calls expand by count and for_each.
  - evaluateCall evaluates a call's count and for_each in the caller (callDecoder, sharing the
    caller's input budget) and reuses resourceDecoder.expand: sorted keys, a `[*]` placeholder
    with unknown_expansion or invalid_expansion, and at most 10,000 instances per call
    (instancesLimited).
  - Each instance is evaluated with count or each bound in its inputs (moduleInputs with the
    instance's values). Its address is `module.a[0].module.b["k"]`, which also prefixes its
    resources. ModuleInstance gains Key and ExpansionUnknown.
  - The caller sees a tuple (count), an object by key (for_each), or one object. Placeholders
    and cut expansions are unknown, never partial.
  - A tree has at most 10,000 module instances, checked before each instance starts.
  - Argument source evaluated again per instance is charged to the caller's call expansion work
    (maxExpansionWork). That counts toward the tree's expansion budget (ADR 0012).
- Files: internal/terraform/{modules_eval.go,modules_inputs.go,resources.go,resources_expand.go,
  modules_expand_test.go,modules_eval_internal_test.go},
  docs/adr/0012-expand-module-calls-by-count-and-for-each.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test:
    - no instance values in inputs, placeholder value known, no key suffix;
    - no tree cap, no per-call limit flag;
    - no argument-source charge, no fold into tree expansion.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: call arguments were evaluated again per instance with nothing charged. A 250 KB
      argument took 124 ms per instance, so `count = 10000` would take about 20 minutes. Fixed
      with a regression test.
    - Minors: tree-cap tests at 9,999 and 10,000 leaves were added, and the invalid_expansion
      wording is now neutral.
  - Round 2: APPROVE, no findings. The probe now runs in 8.9 s at its worst nesting.
- Next: T-0107d (modules.json), then T-0107e.

## 2026-10-09 · T-0107d · done
- What: remote modules resolve through a trusted module manifest.
  - LoadModuleTree takes TreeOptions (trusted pipeline input). With TrustModuleManifest set
    (off by default), it reads the root module's .terraform/modules/modules.json (readManifest).
    The manifest is capped at 1 MiB and 10,000 entries, and must be one JSON value with no
    duplicate keys. Otherwise it is ignored, with module_manifest_invalid.
  - Remote calls resolve per call by their key (ModuleNode.key, the dot-joined call names). The
    entry must record the call's source, or the source prefixed with `registry.terraform.io/`;
    otherwise the call is stale_manifest. Its Dir must not be empty, absolute or a Windows
    volume, and must pass confinedDir (split out of localSource).
  - Remote warnings are reported per call, in load. ADR 0013 records the trust model. Threat
    model T2 and T4 are updated, and T-0109 gains the flag and gap mappings.
- Files: internal/terraform/{modules_manifest.go,modules_tree.go,modules_manifest_test.go,
  modules_tree_unix_test.go, and the LoadModuleTree callers in tests},
  docs/adr/0013-resolve-remote-modules-through-the-module-manifest.md,
  docs/security/threat-model.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test:
    - the trust gate, the source check, the duplicate check, the trailing-data check;
    - flat keys, the absolute/volume check, the entry cap, the empty-Dir check.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: a manifest committed in a pull request was trusted by default. A pull request
      could replace an unresolved_module gap with a benign module copy and pass
      `--fail-on-gaps` (T4), and the ADR's `terraform init` mitigation was wrong.
    - Fixed: resolution is off by default and needs trusted input, and the ADR and threat
      model are corrected.
    - Minors: the shorthand-source limitation is recorded and tested, T-0109 gap mappings were
      added, and entry-limit and empty-Dir tests were added.
  - Round 2: APPROVE, no findings.
- Next: T-0107e (local children that no root instantiates).

## 2026-10-09 · T-0107e · done
- What: no local module is skipped silently.
  - EvaluateRoots evaluates mods.Roots, then scans as orphan roots every local child that no
    tree instantiated. Skipped instances count as covered, because they are reported.
  - Candidates come from ClassifyModules (Children and the new CalledBy) and from every loaded
    tree's resolved calls, which also reach calls made inside hidden modules.
  - Orphans:
    - get an uninstantiated_module warning;
    - use their own defaults only (no pipeline vars);
    - never trust the module manifest;
    - may be hidden directories (TreeOptions.allowUndiscovered).
  - Orphans called by other orphans wait. When all wait, the first cycle member goes first
    (firstInCycle). ADR 0014 records the decision.
  - The T-0107g wall-clock check in TestEvaluateTreeBoundsTheWholeTree failed 1 time in 3 under
    `-race -shuffle=on` (20.14 s). It is now scaled by raceSlowdown (10 under race, 1 otherwise),
    and the deterministic assertions are unchanged.
- Files: internal/terraform/{modules_roots.go,modules_roots_test.go,modules.go,modules_tree.go,
  modules_test.go,modules_tree_test.go,modules_eval_test.go,race_ext_on_test.go,
  race_ext_off_test.go}, docs/adr/0014-scan-uninstantiated-local-modules-as-roots.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test:
    - no waiting for orphan callers, all-in-cycle promotion, first-by-path fallback;
    - skipped instances not counted as covered, no allowUndiscovered;
    - no tree walk, orphans trusting the manifest.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: calls made inside hidden modules were never candidates, so their `count = 0`
      children were silently skipped. Fixed by walking the loaded trees.
    - Minors: the cycle fallback could pick a non-member and scan a module twice; orphans
      inherited manifest trust. Both fixed.
  - Round 2: APPROVE. Its minor (ADR wrapping) is fixed.
- Next: T-0107f (paths inside child module instances).

## 2026-10-09 · T-0107f · done
- What: paths inside child module instances resolve as in Terraform.
  - ParsedModule gains baseDir and pathModule. EvaluateTree sets them for each child to the
    tree's root directory and the child's path from it (pathFrom). A root module keeps its own
    directory and ".".
  - pathObject is per instance: path.module is the instance's path, path.root is "." (it was
    unknown), and path.cwd is unknown.
  - file, fileexists and templatefile join relative paths to the base directory (filePath). They
    are confined to the scan root through os.Root rather than to a sub-root of the module
    directory, because a child's path.module can leave the root module directory. Templates are
    named by their scan-root path.
  - ADR 0015 records the boundary change, and docs/reference/terraform-functions.md is
    rewritten to match.
  - T-0120 (needs-human) aligns the harness standards (hcl-evaluation reference, threat model)
    with ADR 0013, ADR 0014 and ADR 0015.
- Files: internal/terraform/{functions_files.go,resources.go,locals.go,parse.go,modules_eval.go,
  modules_paths_test.go,functions_files_internal_test.go,functions_files_unix_test.go},
  docs/adr/0015-resolve-file-paths-against-the-root-module.md,
  docs/reference/terraform-functions.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test: no instance paths, no base directory, path.root unknown,
    no scan-root check.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: the user-facing reference still described per-module confinement.
    - Minors: stale comments; harness references needing a human; missing tests for a
      manifest-resolved module's path.module and for a child template's diagnostic location.
    - All addressed; the harness part is T-0120.
  - Round 2: APPROVE, no findings.
- Next: T-0108 (references and provider versions); T-0107 is complete.

## 2026-10-09 · T-0108a · done
- What: per-attribute references.
  - T-0108 was split into a (references) and b (providers and lock file). T-0109 depends on
    T-0108b.
  - resourceDecoder.references records an expression's addresses:
    - resources, data, ephemeral resources and module calls, with a literal index kept
      (referenceWithIndex) and qualified with the instance's module address (addrPrefix);
    - plus the references of the locals and variables it uses.
  - Module inputs carry their references and incompleteness into the child's variables
    (Input/Variable.References and ReferencesIncomplete). Locals inherit variables' references
    within their budget.
  - Resource.References (by dot-joined attribute path), Output.References and qualified
    depends_on are recorded.
  - One per-module budget (attrRefs, 2^17 entries; tree refs dimension) is checked against an
    upper bound before any list is built, with results memoized by source range. inspect also
    memoizes inspectExpr.
  - Dynamic blocks whose for_each refers to anything, or that are invalid, mark the resource
    incomplete. T-0109 must surface ReferencesIncomplete.
- Files: internal/terraform/{references.go,references_test.go,resources.go,resources_json.go,
  resources_dynamic.go,locals.go,locals_test.go,locals_internal_test.go,variables.go,
  modules_inputs.go,modules_outputs.go,modules_eval.go,modules_eval_internal_test.go,parse.go},
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test:
    - no qualify, no input references, no index, no depends_on qualify;
    - no cap, iterator silent, no upper bound;
    - dropping input incompleteness, locals ignoring variable incompleteness, no dynamic marking.
  - Inspecting expressions twice had pushed TestDecodeResourcesManyReferences over 64 MB
    under -race; memoizing inspectExpr fixed it.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: a var.x expanded its input's whole reference list into every local and resource
      before any cap (3.7 GB live, 37 GB allocated).
    - Major: input incompleteness was dropped (fail-open).
    - Minors: boundary tests, dynamic for_each references, a stale doc.
    - All fixed. The reviewer's repros now run in 0.45 s with a 145 MB heap.
  - Round 2: APPROVE. Its minor, over-flagging incompleteness (safe), is follow-up T-0121.
- Next: T-0108b (providers and locked versions).

## 2026-10-09 · T-0108b · done
- What: provider sources and locked versions.
  - RequiredProviders (per instance, memoized) reads required_providers without evaluation:
    - the object form (quoted keys included) and the legacy string form;
    - sources normalized to lowercase [host/]namespace/type, with registry.terraform.io as the
      default host;
    - undeclared names default to hashicorp, and "terraform" to terraform.io/builtin/terraform;
    - an unreadable, non-literal or invalid source, or a non-object entry, gives "" with
      invalid_provider_source, never a silent default.
  - Resource.Provider comes from the provider meta-argument's local name, else the type prefix.
    ProviderConfigs lists provider blocks (local name, literal alias, source) on
    ModuleInstance.Providers.
  - ReadLockFile reads `.terraform.lock.hcl` with a 1 MiB cap and the nesting guard before
    parsing, and keeps only valid addresses with exact literal versions.
    - Anything unusable (size, depth, syntax, a malformed block, a bad address, a non-exact
      version, a duplicate, not a regular file) is a lock_file_invalid warning; reading never
      fails the scan.
    - RootResult.ProviderVersions holds the result, and T-0109 maps both codes to gaps.
- Files: internal/terraform/{providers.go,providers_test.go,resources.go,parse.go,
  modules_eval.go,modules_roots.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test (12 mutations): lowercase, legacy, the nesting guard,
    literal versions, duplicates, the config name, unwrap, non-literal and non-object sources,
    builtin, semver, content diagnostics.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: an unreadable source (a quoted key, a template, a non-object entry) silently fell
      back to hashicorp/<name>.
    - Minors: the builtin terraform provider; a lock file that is not a regular file failed the
      scan; dropped parse diagnostics; no version format check; size-boundary and kept-version
      assertions.
    - All fixed.
  - Round 2: APPROVE. Its minors (a dead error result, a nil-subject diagnostic) are fixed.
- Next: T-0111 or the next ready M1 task; T-0109 waits on T-0113, T-0115 and T-0116.

## 2026-10-09 · T-0111a · done
- What: per-file parse memory is bounded.
  - T-0111 was split into a (per file), b (the trees a scan keeps), c (index chains) and d (the
    holdsDynamicSource memo).
  - DefaultLimits MaxFileSize is now 1 MiB instead of 5 MiB (ADR 0016). Larger files are
    too_large skips, which become gaps.
  - TestParseMemoryPerFile measures live heap (diagnostics included) for nine worst-case shapes
    at the limit. Lexing must stay under 320 MB and parsing under 192 MB.
  - Parsing keeps at most 100 diagnostics per file, then one too_many_diagnostics that is an
    error once any dropped one is. This covers hcl syntax diagnostics, unsupported blocks and
    arguments, and tfvars diagnostics, all through parseDiag. Evaluation diagnostics are not
    counted.
- Measurements (live heap at 1 MiB, lexer / parse; the 5 MiB figures in parentheses):

  | shape | lexer | parse |
  |---|---|---|
  | distinct `aN=1` lines | 48 MB (229) | 47 MB (222) |
  | one long list | 117 MB (560) | 84 MB (421) |
  | duplicate `a=1` lines | 117 MB | 144 MB |
  | operator chain | 117 MB | 131 MB |
  | unary chain | 117 MB | 141 MB |
  | empty blocks | 117 MB | 130 MB |
  | negations | 117 MB | 122 MB |
  | invalid characters | 286 MB | 168 MB |
  | JSON list | — | 80 MB (401) |

  - Realistic HCL keeps about 22 MB per MiB (89 bytes per token).
  - Before the cap, diagnostic floods kept 118 MB (`@`), 45 MB (unsupported blocks) and
    20 MB (top-level arguments) per file; tfvars floods kept 117 MB and 21 MB.
- Files: internal/terraform/{discover.go,discover_test.go,parse.go,variables.go,
  parse_memory_internal_test.go,locals_test.go}, docs/adr/0016-lower-the-file-size-limit-to-1-mib.md,
  docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - TestParseMemoryPerFile failed at 5 MiB (560/421 MB) and passes at 1 MiB.
  - Mutation checks each fail a test: no cap, no severity upgrade, unsupported() uncapped, the
    tfvars undeclared warning uncapped.
- Review: iace-reviewer, 4 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: the shapes were not the worst cases. Major: diagnostics were unbounded.
    - Minors: ADR figures, the tfvars cap, a uint64 wrap.
  - Round 2: CHANGES_REQUIRED.
    - Major: unsupported blocks and arguments bypassed the cap.
    - Minors: evaluation diagnostics were counted; T-0109 mapping.
  - Round 3: CHANGES_REQUIRED. Major: tfvars diagnostics were uncapped.
  - Round 4: APPROVE. Its minor (per-name counting when a file is read twice) goes to T-0121.
- Next: T-0111b (scan-wide parse budget).

## 2026-10-09 · T-0111b · done
- What: the syntax trees a scan keeps are bounded.
  - ParseBudget (budget.go) is carried as a pointer in Limits and shared by every ParseModule
    of a scan. DefaultLimits creates one, and EvaluateRoots creates one when there is none.
    MaxScanTokens is 3,000,000.
  - lexCost: an HCL file costs its lexer tokens (from the nesting guard's lex) plus one per 30
    source bytes; a JSON file costs its bytes.
  - A file is parsed, and its source kept, only when its cost fits. Otherwise it gets a
    parse_limit warning naming it (T-0109 maps it to limit_exceeded). ADR 0017 records the
    decision.
- Measurements (kept heap per budget token at 1 MiB): operator chain 128, nested blocks 127, list
  82, call arguments 82, JSON list 81, realistic 74, long literal 60, long comment 30. So the
  budget keeps at most about 384 MB, plus one file's ~450 MB transient peak (ADR 0016). Realistic
  HCL costs about 380,000 budget tokens per MiB.
- Files: internal/terraform/{budget.go,budget_internal_test.go,nesting.go,parse.go,discover.go,
  modules_roots.go}, docs/adr/0017-bound-the-syntax-trees-a-scan-keeps.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - Mutation checks each fail a test: no budget check, a tokens-only cost, src stored before
    the budget, no EvaluateRoots fallback.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: a token-only cost let 1 MiB literals cost 18 tokens.
    - Majors: a refused file kept its source; 90 B per token understated the operator chain.
    - Minor: a budget per call.
    - All fixed.
  - Round 2: APPROVE. Its minors (a fallback test, nested blocks and JSON shapes, stale
    comments, RSS versus live heap noted for T-0109's benchmark) are done.
- Next: T-0111c (index chains).

## 2026-10-09 · T-0111c · done
- What: postfix chains in evaluated expressions are bounded.
  - checkChains runs inside scanTokens whenever maxOps is set: inspectExpr, JSON templates,
    --var expressions and templatefile templates. It refuses more than maxChain = 1,024 nested
    postfix steps, so the expression is unknown with expression_too_complex (T-0109 maps it to
    limit_exceeded). Parsing is not limited.
  - The count follows the syntax tree's depth. It carries through parentheses, index keys, call
    arguments and `.*`/`[*]` splats. It resets at operators, commas and any open bracket other
    than an index `[`. `[local.k]` counts two per step, a conservative overcount. ADR 0018 records
    the decision.
- Measurements: before the fix, a 1 MiB chain (about 350,000 steps) allocated about 600 MB and
  used about 128 MB of stack. After the fix it is refused with no measurable stack, but still
  allocates about 1.1 GB because it is lexed twice (follow-up T-0111e).
- Files: internal/terraform/{nesting.go,evalguard.go,functions_files.go,chains_internal_test.go},
  docs/adr/0018-bound-postfix-chains-in-evaluated-expressions.md, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. The new bypass tests fail under round 1's per-level count.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: parentheses, `.*` splats and index keys bypassed the per-level count.
    - Minors: no measurement after the fix; evalExpr's message wording.
    - All fixed. T-0111e added.
  - Round 2: APPROVE. Its minor: an owner edit to .gitignore (`/materials/`) appeared in the
    tree during the iteration. It was left out of this commit, stashed as "owner edit: ignore
    /materials/", and restored on main afterwards.
- Next: T-0111d (memoize only containers in holdsDynamicSource).

## 2026-10-09 · T-0111d · done
- What: holdsDynamicSource walks and memoizes only JSON objects and arrays.
  - jsonContainer unwraps the expression and calls its own ExprMap/ExprList. These return nil
    for anything else, where hcl.ExprMap/hcl.ExprList built an error diagnostic for every scalar.
  - A scalar is data at once, before the memo lookup.
- Measurements: a flat 2.4 MB array of 1.2M numbers allocated 643 MB and kept 1,200,002 memo
  entries. It now stays under the test's 32 B per source byte (77 MB) with one entry.
- Files: internal/terraform/{resources_json.go,resources_json_internal_test.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. TestHoldsDynamicSourceScalarsAreCheap fails without the
  change (reviewer confirmed on a scratch copy of HEAD).
- Review: iace-reviewer, 1 round: APPROVE. Its minor (pin `{"dynamic": {}}` and `[]` as true,
  `null` as false) was added to TestHoldsDynamicSource.
- Next: T-0111e (lex an evaluated expression once).

## 2026-10-09 · T-0111e · done
- What: an evaluated expression is lexed and checked once per evaluation stage.
  - inspectExpr is memoized on ParsedModule by file and source range. It replaces the resource
    decoder's own memo, so locals, module inputs, variables, type expressions and resources
    share it.
  - setSource/dropSource replace the direct m.src writes (file parse, temporary tfvars and
    --var sources) and forget that file's inspections, so a reused name is never judged by
    earlier bytes.
  - forgetInspections clears the memo when a stage ends (EvaluateVariables, evaluateLocals,
    ModuleInputs, EvaluateModuleVariables, decodeResources). The memo is about 11 times the
    source it covers, so it is not kept for the whole scan.
- Measurements: EvaluateLocals on a refused 1 MiB chain allocated 1.23 GB, twice one inspection
  (613 MB). It now stays within 1.25 times one inspection.
- Files: internal/terraform/{evalguard.go,parse.go,variables.go,locals.go,modules_inputs.go,
  resources.go,references.go,chains_internal_test.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - TestRefusedExpressionIsLexedOnce fails without the memo (2 times one inspection).
  - TestInspectionsFollowTheSource fails when the invalidation and the stage clearing are
    removed (mutation run).
- Review: iace-reviewer, 1 round: APPROVE. Its two minors are done: a test for memo invalidation,
  and clearing the memo per stage (it would otherwise keep about 11 times the source per module
  instance for the whole scan). Its note: --var values are still lexed twice (a scanTokens
  before parsing protects the parser), which is accepted because the CLI input is trusted and
  small.
- Next: the next ready M1 task.

## 2026-10-09 · T-0112a · done
- What: overrides of everything except resources and data sources are merged with Terraform's
  semantics (ADR 0019).
  - T-0112 was split. This task covers the blocks read through hcl.Body; T-0112b covers
    resource and data overrides, which the resource decoder reads by concrete body type.
  - ParseModule sets override blocks aside and merges them after every other file, in file
    name order.
    - variable, output, module and provider blocks (a provider by name and alias) merge through
      mergedBody: attributes replace, and nested blocks replace by type.
    - locals merge by name.
    - terraform settings replace by key, required_providers by provider name, and backend and
      cloud replace each other (maskedBody).
  - Errors, as in Terraform: an override without a base (override_without_base), and depends_on
    in a module or output override (override_unsupported).
  - Resource, data and other override blocks are reported per block as override_not_merged.
  - Literal module sources and provider aliases decide JSON syntax by the expression's file
    (inJSON). addHCLDiags names a diagnostic's own file.
  - Behaviour change: a module source override now redirects the call, as in Terraform.
    TestUninstantiatedChildrenAreScannedAsRoots now expects ./evil to be called and ./good to be
    an orphan.
- Files: internal/terraform/{override.go,override_internal_test.go,parse.go,parse_test.go,
  modules_tree.go,providers.go,modules_roots_test.go},
  docs/adr/{0019-merge-overrides-with-terraform-semantics.md,0005-...md},
  docs/security/threat-model.md (T14), docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. TestOverrideMergingIsLinear parses a 1 MiB override file of
  each kind in about 1.5 s (2.4–3.5 s per subtest under -race, against a 20 s bound).
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: merging was super-linear in untrusted override blocks (2,000 locals overrides
      took 100 s).
    - Minors: duplicate locals were hidden, diagnostic file names, PartialContent dropped
      required checks, depends_on, test gaps.
    - All fixed.
  - Round 2: APPROVE. Its note: if a slow runner trips the linear test's 20 s bound, raise it
    (the old cost would take hours).
- Next: T-0112b (resource and data overrides).

## 2026-10-09 · T-0112b · done
- What: resource and data overrides are merged with Terraform's semantics (ADR 0019).
  - applyOverrides attaches each override to the resource or data block it names.
    - A missing base is override_without_base.
    - depends_on is override_unsupported, as for module calls and outputs.
    - moved, import and removed blocks in override files are errors. ephemeral, check and
      action overrides change nothing iace checks.
  - The resource decoder layers the bodies (overriddenBody, resources_override.go), for HCL and
    JSON alike.
    - A layer skips the top-level attributes and nested block types, static or dynamic, that a
      later layer sets. So replaced values are never evaluated, recorded in Attributes,
      referenced, or counted as unknown.
    - The last layer per name is indexed once, so decoding stays linear.
    - count, for_each, provider and lifecycle arguments replace layer by layer. As in
      Terraform, an ignore_changes list replaces only when it is non-empty, and `all` stays.
    - Cost and structure are summed over the layers.
  - override_not_merged and ADR 0005's accepted risk are retired. Threat model T14 is
    mitigated.
- Files: internal/terraform/{resources_override.go,resources.go,resources_json.go,override.go,
  parse.go,resources_override_internal_test.go,resources_override_test.go,
  override_internal_test.go,parse_test.go}, docs/adr/{0019,0005}, docs/security/threat-model.md,
  docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - TestWeakeningOverrideReachesTheScan: `acl = "public-read"` from an override reaches the
    evaluated resource in the root and in a child module.
  - Mutations fail tests: ignoring overrides fails all five decoder tests; always appending
    JSON base dynamics, or dropping JSON dynamic labels from topNames, each fails a subtest.
  - 1 MiB of overrides of one resource decodes in about 0.3 s.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: depends_on in a resource override must be an error, as in Terraform. The
      acceptance wording was wrong too and has been corrected.
    - Minors: lifecycle edge cases, JSON dynamic tests that let mutations survive, a doc
      comment, and input-document proof.
    - All fixed. Added a T-0109 acceptance bullet (weakening override fixture in the golden
      set) and follow-up T-0112c (report duplicate resource declarations).
  - Round 2: APPROVE. Its comment-wrap minor is fixed.
- Next: T-0112c or the next ready M1 task.

## 2026-10-09 · T-0112c · done
- What: a resource or data source declared twice in a module is an error (duplicate_resource)
  at the second header, as in Terraform. The second copy is not decoded, as for duplicate
  variables, outputs, locals and module calls. The first copy, into which overrides merge, is the
  one decoded. A managed resource and a data source may share a type and name.
- Files: internal/terraform/{resources.go,resources_override_internal_test.go,
  resources_override_test.go}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. TestDuplicateResourcesAreErrors failed before the change.
  It checks positions, HasErrors, the decoded copy with an override applied, and that resource
  and data are distinct. TestDuplicateResourceInExpandedChild checks that a duplicate in a
  count = 2 child is reported once on each of its 2 instances.
- Review: iace-reviewer, 1 round: APPROVE. Its three minors are done: the DecodeResources doc
  comment, the override case, and the expanded-child test.
- Next: the next ready M1 task.

## 2026-10-09 · T-0113 · done
- What: for-expression cost is bounded (ADR 0020).
  - Every for expression iace evaluates is rewritten after parsing to iterate over
    `__iace_for(coll, bodyBytes, iteratorUses, __iace_refs(...), __iace_elems(...))`. This
    covers module files, tfvars, `--var` and templatefile templates.
  - The function evaluates the collection as an expression closure, so cty never walks it for
    free. Before the loop runs, it charges the module's function work:
    - the collection's measured size;
    - each iteration: 16 plus the body's source bytes, plus the sizes of the values the body
      refers to, or the largest element for values it only indexes;
    - the collection's size once for each use of the iterators.
  - Every measurement stops at the work left and is charged. A refused loop spends only what it
    measured.
  - Over the limit, the for expression is unknown with expression_too_complex ("For expression
    too large").
  - Type constraints that hold a for expression are refused, in HCL and JSON, because typeexpr
    evaluates optional() defaults outside the rewrite.
  - In .tf.json, a value that is a single template string is evaluated by iace, as hcl would.
    A for in a nested JSON template string is refused.
  - The internal functions are in scope only for expressions that need them.
- Files: internal/terraform/{forexpr.go,forexpr_internal_test.go,evalguard.go,functions.go,
  functions_files.go,parse.go,variables.go}, docs/adr/0020-charge-for-expression-iterations.md,
  docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - Three nested fors over 1,000 elements (about 1e9 iterations) are limited in about 2 s.
  - A 200 KB string per element: 393 MB before the change (1.36 GB as a `%{ for }`), now under
    100 MB. The mutation `__iace_refs` = 0 reproduces 393/325/1,365 MB.
  - The reviewer's measuring probes are now limited (unfixed, 33 s to about an hour) and are
    regression tests.
  - A refused loop leaves the module's work for later calls (mutation-checked).
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blockers: type-constraint defaults escaped the rewrite; per-iteration value size was not
      charged (393 MB).
    - Minors: an HCL optional default turned into an error; error summaries in contexts with no
      functions.
  - Round 2: CHANGES_REQUIRED. Blockers: the collection and the references were walked for free
    (33 s to hours).
  - Round 3: APPROVE. Its minor (a refused loop spent all remaining work) is fixed and tested.
  - Accepted and documented: the estimate is conservative (nested local.m[k] is charged per
    outer iteration), and one cosmetic error summary changes.
- Next: T-0113a / T-0113b or the next ready M1 task.

## 2026-10-09 · T-0113a · done
- What: template for directives are charged the strings they produce, and the iteration weight
  is set by measurement (ADR 0020).
  - rewriteForExprs wraps the body of each `%{ for }` directive (a TemplateJoinExpr's
    ForExpr) in `__iace_val` (forResultFunction). It charges each iteration's string up to the
    work left. Over the limit it returns unknown with forLimited, keeping the marks.
  - Profiling the three-level template (583 MB total) showed the strings were about 16 MB. The
    rest was hcl's per-iteration overhead, about 1.3 KB per iteration and short-lived (the live
    heap stays at a few MB). So forIterationWork goes from 16 to 64. It bounds time: about
    125k small-body iterations per module tree instead of about 500k.
  - The test helper parseFilesModule now passes only .tf and .tf.json files to ParseModule, as
    discovery does.
- Files: internal/terraform/{forexpr.go,forexpr_internal_test.go,functions_internal_test.go},
  docs/adr/0020-charge-for-expression-iterations.md, docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - Three nested directives over 1,000 elements: 0.3 s and 220 MB total, against 0.7 s and
    583 MB before.
  - 300 one-element levels around a 200 KB string: limited and under 150 MB, against 290 MB
    and evaluated in full without the wrap (mutation-checked).
  - forResultFunction is tested just below, at and just above the limit, with exact charging
    and marks.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: no test exercised the string charge.
    - Minors: the weight was justified by the wrong metric (it bounds time, not memory), the
      ADR header, and a duplicate fixture.
    - All fixed. T-0113c added (measure realistic trees against the limit).
  - Round 2: APPROVE.
- Next: T-0113b, T-0113c or the next ready M1 task.

## 2026-10-09 · T-0113c · done
- What: for-expression work was measured on realistic module trees, and the tree's function
  budget was sized from the measurements (ADR 0021).
  - Fixtures in internal/terraform/testdata/realistic:
    - fanout: for_each over 150 subnets, each a module instance with nested for expressions
      over 10 ports × 10 peers, cidrsubnet, replace, flatten, and a dynamic block of 100 rules;
    - nested-maps: 10 environments × 30 services, flattened to 300 entries and looked up by key;
    - templates: count = 50, templatefile with three %{ for } directives.
  - TestRealisticTreesStayUnderTheWorkLimit requires each tree to have:
    - no limit diagnostic and no unknown resource value;
    - the expected instance and resource counts;
    - at most half the tree's function work, and each instance at most half of maxFunctionWork.
- Measurements (maxFunctionWork = 8,388,608 per module):
  - templates: 1,146,915 (13.7% of one module).
  - nested-maps: 723,126 (8.6%).
  - fanout: about 67,800 per instance, of which about 51,600 are for-expression charges (16,200
    with them disabled; weight 0 alone did not help). At 200 instances, about 13.6M against the
    tree's former 8.4M: the tree was truncated and 242 of 400 resources were decoded.
  - After the change (tree function work 4 × maxFunctionWork = 33,554,432), fanout at 150
    instances uses 10,337,515 (30.8%).
  - Not fixed here:
    - fanout at 200 also reaches the tree's expansion work (about 11,700 per instance against
      2^21; ceiling about 179 instances, T-0113d).
    - `lookup(local.m, k, null)` in a for body over a map reaches one module's work from about
      140 entries (T-0113e).
- Files: internal/terraform/{realistic_internal_test.go,modules_eval.go,testdata/realistic/**},
  docs/adr/0021-give-a-module-tree-four-modules-of-function-work.md, docs/adr/{0009,0020} (header
  "Amended by" lines), docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - Reverting the budget makes the new test fail: 242 resources, module_work_limit.
  - The existing tree-budget tests still reach truncation.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: the whole-map lookup idiom was missing; it is recorded as T-0113e.
    - Minors: test strength, comments, the ADR immutability of 0020, ADR 0021 wording. All
      fixed.
  - Round 2: APPROVE. Its minor (ADR 0021 now lists the test's checks) is fixed.
- Next: T-0113b, T-0113d, T-0113e or the next ready M1 task.

## 2026-10-09 · T-0113d · done
- What: a module tree's expansion work is four modules' worth (ADR 0022, amending ADR 0009). The
  per-module budget (2^21) is unchanged. The realistic fan-out is tested at 200 instances.
- Measurements:
  - 200 instances: 358 of 400 resources before; 400 of 400 after.
  - Expansion work 2,350,131 of 8,388,608 (28%, call arguments included); function work 41%.
  - The scan takes about 1.0 s, so at most 431 ns per byte.
  - Worst case with overshoot: about 12.6 MB, 5 to 8 s. The new "expansion" case of
    TestEvaluateTreeBoundsTheWholeTree (1,000 calls of a 300-operator body under count = 10,000)
    stops at about 5 instances in 4.2 s.
- Files: internal/terraform/{modules_eval.go,modules_eval_test.go,realistic_internal_test.go,
  testdata/realistic/fanout/main.tf}, docs/adr/{0022-give-a-module-tree-four-modules-of-expansion-work.md,
  0009 (header)}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass. With the old budget, the realistic test fails (358 of 400,
  expansion at 99.7%).
- Review: iace-reviewer, 1 round: APPROVE. Its three minors are done: the ADR worst case
  includes the overshoot, the test charges call expansion as the tree does, and a behaviour
  and time test for the expansion budget.
- Next: T-0113b, T-0113e or the next ready M1 task.

## 2026-10-09 · T-0113e · done
- What: `lookup` no longer walks its map, so `{ for k in keys(local.m) : k => lookup(local.m, k,
  null).x }` stays within a module's work (ADR 0023).
  - Measured: one bounded lookup call costs about 124 ns per unit of its map, because cty's
    ContainsMarked and UnmarkDeep, the wrapper's two measurements, and IsWhollyKnown each walk
    the whole map. A walk alone is about 15 ns per unit, and building values about 43. The
    charges were accurate, so charging less was unsafe. A size cache was not possible: cty
    values have no identity, and cty walks every argument anyway.
  - So rewriteForExprs renames every 2- or 3-argument lookup to `__iace_lookup`. It takes
    expression closures (cty sees capsules), evaluates them itself, reads the element in
    constant time and charges 1 + the result's size.
  - Errors match Terraform's, checked in its order, and never quote the key.
  - ADR 0020's reference charge treats lookup's map like an indexed reference.
  - Semantics now as in Terraform for marks: the result keeps the map's, the key's and the
    element's own marks, where the old bounded lookup took on every mark in the map. A known
    element of a partly unknown map is returned (Terraform resolves to it).
- Files: internal/terraform/{lookup.go,lookup_internal_test.go,forexpr.go,forexpr_internal_test.go,
  functions.go,parse.go,functions_terraform_internal_test.go,realistic_internal_test.go,
  testdata/realistic/nested-maps/main.tf}, docs/adr/{0023-evaluate-lookup-without-walking-its-map.md,
  0020 (header)}, docs/reference/terraform-functions.md, docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - nested-maps with the idiom over 300 entries: 878K work, about 10% of a module. Before, it
    was limited and all 300 desired_count values were unknown.
  - A body copying a 1,000-entry map on every iteration is still limited.
  - The lookup charge is tested below, at and above the limit; marks (map, element, key,
    default) and error parity are tested.
  - The zero-argument rewrite crash is a regression test (mutation-checked).
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Blocker: a for body with a zero-argument call panicked during parsing.
    - Minors: error parity, mark tests.
    - The reviewer accepted the sensitivity and unknown semantics.
  - Round 2: APPROVE. Its minors are fixed: the key is no longer quoted in an error, and the
    ADR lists the error order.
- Next: T-0113b or the next ready M1 task.

## 2026-10-09 · T-0113b · done
- What: for expressions in .tf.json template strings nested in objects and arrays are evaluated
  and charged instead of being refused (ADR 0024, amending ADR 0020 and 0023).
  - evalJSON evaluates a JSON value member by member, as hcl's decoder does:
    - arrays become tuples, and objects keep keys as templates;
    - invalid, null and duplicate keys are errors, and an unknown key makes the object unknown;
    - each template string is parsed from the byte after its quote and rewritten
      (jsonStringTemplate).
  - Every JSON value evaluated with a context now goes through it. That also fixes an existing
    crash: hcl's decoder panics on a sensitive object key, which untrusted input could
    trigger, and evalJSON reports it as an error.
  - lookup in JSON templates is rewritten too.
- Files: internal/terraform/{forexpr.go,evalguard.go,forexpr_internal_test.go},
  docs/adr/{0024-evaluate-json-values-member-by-member.md,0020 (header),0023},
  docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - TestJSONForExpressions: small nested fors evaluate exactly (object values, array elements,
    keys); about 1e9 iterations at the top level and nested are limited.
  - TestEvalJSONMatchesHCL matches hcl on values and errors, including templates that fail to
    parse or evaluate.
  - TestJSONSensitiveKeysAreErrors: restoring hcl's evaluation for plain values brings back the
    panic (mutation-checked).
- Review: iace-reviewer, 1 round: APPROVE. Both minors are done: the existing sensitive-key
  crash (now fixed by routing every JSON value through evalJSON), and tests for the marked key
  and the parse and evaluation failures.
- Next: the next ready M1 task.

## 2026-10-09 · T-0114 · done
- What: the locals size estimate charges the used part of a value (ADR 0025).
  - A use with static steps after its name (attribute steps and literal indexes, legacy `.0`
    included) is charged the size of the sub-value the steps reach (staticSteps, hcl's
    conversions).
  - Dynamic indexes and splats (where Variables() ends a traversal), unresolvable steps and
    locals not yet evaluated are still charged the whole value, so the estimate stays an upper
    bound.
  - Path sizes are cached by their text. Every measurement is charged to the module's function
    work. With no work left, the whole value's size is charged without walking.
- Files: internal/terraform/{locals.go,locals_estimate_internal_test.go},
  docs/adr/{0025-charge-the-used-part-of-a-value-in-the-locals-estimate.md,0020 (header)},
  docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - Six reads of a field of a 45 KB map are no longer refused: attribute, string index, list
    index, variable, legacy step, sensitive base, unknown midway and module output, all
    refused before.
  - Dynamic index, splat, whole value and large element are still refused (a mutation that
    charges whole fails the first group).
  - 3,000 aliased paths into a 120K list measure at most 70 and stay within the function
    work; uncharged, they took 66 s.
- Review: iace-reviewer, 3 rounds.
  - Round 1: CHANGES_REQUIRED. Major: an uncached per-occurrence walk (67 s for 3,000 locals).
    Minors: untested branches.
  - Round 2: CHANGES_REQUIRED. Major: the text cache could be bypassed by aliases and
    overlapping paths (80 s).
    My round-2 message wrongly claimed the gates had passed, before I read the result. The
    test gate had failed on a 60 s wall-clock test, which was replaced by deterministic tests.
  - Round 3: APPROVE. Its minor (document the charge) is ADR 0025.
- Follow-up: T-0114a (an existing walk of a large input per local for function calls and
  operators: about 140 s for 3,000 `length(var.c.l)`).
- Next: T-0114a or the next ready M1 task.

## 2026-10-10 · T-0114a · done
- What: locals that walk a large input are charged before they walk it (ADR 0026).
  - The profile showed the walks inside cty: Function.Call → returnTypeForValues →
    ContainsMarked (and unmarking and known checks) on every argument of every call and operator
    (operators are cty stdlib functions). They run before iace's bounded wrapper can refuse.
  - walksArguments flags calls, binary and unary operators, and for expressions (rewritten to
    __iace_for); .tf.json expressions are assumed to walk.
  - evalLocal charges such a local the inputs' part of its size estimate (ADR 0025, without its
    own source) × argumentWalkWork (4) before evaluating it. If that is unaffordable, the local is
    unknown with a function_limit warning and nothing is walked.
- Measurements:
  - 3,000 locals over a 120,000-element list take 0.8 s (`!= null`) and 1.7 s (`length`), the
    same as 300.
  - Before: 300 locals took 15 to 20 s, and the time grew linearly with the number of locals.
  - The walks cost about 400 ns per input unit, hence the weight of 4.
- Files: internal/terraform/{locals.go,locals_walks_internal_test.go},
  docs/adr/{0026-charge-the-inputs-of-locals-that-call-functions.md,0020 (header)},
  docs/plan/BACKLOG.md
- Evidence:
  - `gates.sh full` 13 pass.
  - TestWalkingLocalsAreCharged fails without the charge: 3,000 and 68 locals evaluated, 170 s.
  - TestWalkingLocalChargeIsExact covers below, at and above the limit; TestWalksArguments; and
    TestOrdinaryLocalsAreNotLimited.
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Major: ADR 0026 wrongly claimed that resources, outputs and inputs were bounded; they walk
      for free too (about 20 s for 300). Fixed, and follow-up T-0114b added.
    - Minors: tests added, and follow-up T-0114c (quadratic tuple unification).
  - Round 2: APPROVE.
- Next: T-0114b or the next ready M1 task.

## 2026-10-10 · T-0114b · done
- What: input walks are charged wherever iace evaluates an expression (ADR 0027, extending ADR
  0026).
  - evalBounded charges used × argumentWalkWork before evaluating an expression that walks its
    arguments. It covers resource attributes (per count and for_each instance), count, for_each,
    dynamic for_each, outputs and module inputs. `used` is the sizes of the vars, locals,
    modules, iterators and instance values it refers to.
  - Over the limit, the value is unknown with function_limit and nothing is walked. Locals and
    this path share the chargeWalk helper.
  - variableName resolves var.<name> and var["<name>"]. A bare `var` or a dynamic index counts
    the whole var object, and its sensitivity, in locals and resources.
  - walksArguments no longer counts the closure-taking internal functions (__iace_for, its
    reference functions, __iace_lookup), which walk nothing in cty and charge themselves. This
    fixed a double charge that pushed the realistic fan-out from 41% to 57%; it is 41.9% now.
- Files: internal/terraform/{resources.go,locals.go,resources_walks_internal_test.go,
  locals_walks_internal_test.go}, docs/adr/{0027-charge-input-walks-wherever-expressions-are-evaluated.md,
  0026 (header)}, docs/plan/BACKLOG.md
- Evidence: `gates.sh full` 13 pass.
  - 300 resources, count = 300, 300 outputs and a module called 300 times each evaluate at most
    about 18 times over a 120,000-element list, with function_limit. Without the charge, 69 to
    300 evaluate, taking about 31 s.
  - The var["c"] and bare var forms are bounded in resources and locals.
  - TestBareVarLimitStaysSensitive keeps unknown results sensitive (mutation-checked).
- Review: iace-reviewer, 2 rounds.
  - Round 1: CHANGES_REQUIRED.
    - Majors: var["c"] and bare var were not counted (about 15 s for 300), in resources and in
      locals.
    - Minors: I had edited the merged ADR 0026 (restored; ADR 0027 is new), a shared helper,
      and diagnostic checks.
  - Round 2: APPROVE. Its minor (a sensitivity test) was added.
- Next: T-0114c or the next ready M1 task.
