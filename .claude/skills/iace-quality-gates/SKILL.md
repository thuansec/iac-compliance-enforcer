---
name: iace-quality-gates
description: Definition of done and automated quality gates for iac-compliance-enforcer (iace) — the gates.sh script (quick and full modes), the Makefile target contract shared by the loop, CI and humans, coverage thresholds, discipline checks on the diff (secrets, skipped tests, TODOs, progress log), and the self-review checklist to walk before every commit. Use this before declaring any task done, before every commit, when a gate fails, when creating or changing the Makefile, or when deciding whether work is good enough to ship.
allowed-tools: Bash(bash ${CLAUDE_SKILL_DIR}/scripts/gates.sh *)
---

# Quality gates and definition of done

## Run the gates
```bash
bash ${CLAUDE_SKILL_DIR}/scripts/gates.sh quick   # while iterating: format, vet, short tests, policy tests
bash ${CLAUDE_SKILL_DIR}/scripts/gates.sh full    # before every commit: everything, plus diff discipline
```
- Exit 0 means all checks passed (WARN lines are advisory). Exit 1 means at least one FAIL. Exit 2 means usage error.
- A FAIL shows the last lines of that check's log. Fix the cause, not the check.
- The script fails closed: a missing tool or a crashing command is a FAIL. Only checks whose
  inputs don't exist yet (no go.mod during bootstrap) are SKIPped.
- Before the Makefile exists (between T-0003 and T-0004), Go checks fall back to plain
  `gofmt`/`go vet`/`go test`/`go build`.

## Makefile contract
The Makefile is the single source of commands. CI calls the same targets (`iace-ci-cd`), and the
gates fail if any target is missing. Tools run via `go tool -modfile=tools/go.mod …`, so versions are pinned.

| target | must do |
|---|---|
| `fmt-check` | `golangci-lint fmt --diff` (gofumpt and goimports) shows no changes. Confirm it exits non-zero on a diff; if not, fail on non-empty output; `opa fmt --list --fail policies`; `terraform fmt -check -recursive testdata` when terraform is present (else skip with a message) |
| `lint` | `golangci-lint run`; `regal lint policies` (once policies exist); `actionlint` (once workflows exist) |
| `test` | `go test -race -shuffle=on -count=1 -coverprofile=coverage.out ./...` |
| `cover-check` | overall Go coverage from coverage.out ≥ 80% (`go tool cover -func`) |
| `policy-check` | `opa check --strict --capabilities policies/capabilities.json policies` (no-op with a message before M2) |
| `policy-test` | `opa test --capabilities policies/capabilities.json --coverage --threshold 90 policies` (no-op before M2) |
| `vuln` | `govulncheck ./...` |
| `build` | `CGO_ENABLED=0 go build -trimpath ./...` |
| `tidy-check` | `go mod tidy -diff` for the root module and for `tools/go.mod` |
| `ci` | all of the above, in that order |
| also | `fmt` (apply formatting), `tools` (install pinned tools), `capabilities` (regenerate), `policy-bundle` (M8), `snapshot` (GoReleaser snapshot, M11) |

Each target is reproducible and offline after `make tools` (a warm module cache). Targets never
modify tracked files except `fmt`, `capabilities` and explicit `-update` runs.

## Definition of done (every task)
A task is done only when **all** of these hold:
1. Every acceptance bullet in the backlog task is demonstrably met, by a test or a command whose
   output you looked at.
2. Tests were written first and failed for the right reason before the implementation (`iace-testing`).
3. `gates.sh full` passes in the same working tree you will commit.
4. The self-review checklist below is complete, including the `iace-security` checklist.
5. Docs match behaviour: CLI `--help` and examples, README sections touched, reference docs and
   JSON Schemas for any contract change, plus an ADR if a decision was made.
6. BACKLOG task `[x]` with a `result:` line; PROGRESS entry appended; one Conventional Commit
   that references the task ID.

## Self-review checklist (read your own diff like a reviewer)
**Correctness**
- [ ] Does the change do what the task says, and nothing else? Revert unrelated edits.
- [ ] Edge cases: empty input, unknown values, absent attributes, multiple instances, modules, Windows paths in outputs.
- [ ] Errors: every failure path returns a wrapped error, maps to exit 2 where relevant, and is tested.

**Tests**
- [ ] Would each new test fail if the implementation were reverted?
- [ ] Golden diffs reviewed line by line, and no accidental absolute paths or timestamps.
- [ ] Rules: pass and fail fixtures exist, Rego coverage is held, and fixture attributes were verified against the provider schema.

**Security** (full list in `iace-security`)
- [ ] Untrusted input is confined and size-limited; no execution of scanned content; offline by default.
- [ ] No secret value can reach logs, outputs, caches or prompts.

**Design**
- [ ] Code sits in the right package per `iace-architecture`, and dependency rules hold.
- [ ] Determinism: sorted outputs, injected clock, no map-order leaks.
- [ ] Simplest solution that meets the criteria. No speculative abstractions or dead code.

**Hygiene**
- [ ] No debug prints, commented-out code, stray TODOs (TODOs reference a task ID), or `t.Skip` without a task.
- [ ] Names and doc comments explain intent. The commit message says *why*, not only *what*.

## When a gate fails
1. Read the failure, reproduce it with the single target (`make lint`, `go test ./pkg -run X`),
   then fix the root cause.
2. If the failing check itself is wrong (a false positive, an outdated threshold), do **not**
   bypass it in this task. Finish the task in a way that passes, or stop, record a blocker, and
   propose a separate task to fix the gate with its rationale.
3. Never use `--no-verify`, skip tests, lower thresholds, add blanket `//nolint`, or delete
   failing tests to get green. A gate weakened once is weakened for every later iteration.
