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
