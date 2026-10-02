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
