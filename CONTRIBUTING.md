# Contributing to iace

## Prerequisites
- Go 1.27 or later. go.mod pins `toolchain go1.27.1`; with `GOTOOLCHAIN=auto` (the default) Go
  fetches it when yours is older.
- bash and make. Optional: `terraform`, used only to check the formatting of test fixtures.
- The dev tools (golangci-lint, govulncheck, actionlint, regal, opa) are pinned one module per
  tool under `tools/` and run through `go tool`, so nothing needs a global install. `make tools`
  downloads and builds them once; after that every check works offline except `make vuln`, which
  fetches the Go vulnerability database.

## Everyday commands
| command | what it does |
|---|---|
| `make help` | list the targets |
| `make fmt` | apply gofumpt and goimports |
| `make test` | race-enabled, shuffled tests with a coverage profile |
| `make lint` | golangci-lint, plus regal for policies and actionlint for workflows |
| `make ci` | everything CI runs, in the same order |

## How a change lands
1. Pick one task from [docs/plan/BACKLOG.md](docs/plan/BACKLOG.md) and branch from an up-to-date
   `main` as `<type>/T-xxxx-<slug>`, where type is the Conventional Commit type (`feat`, `fix`,
   `docs`, `test`, `chore`, `ci`, `refactor`).
2. Write the tests first, one or more per acceptance bullet, and watch them fail for the right
   reason before you implement.
3. Run the quality gates: `bash .claude/skills/iace-quality-gates/scripts/gates.sh full`. They
   run every Makefile check plus discipline checks on the diff (no secrets, no `t.Skip` without a
   task ID), and they must pass on exactly what you commit.
4. Mark the task `[x]` with a `result:` line, append an entry to
   [docs/plan/PROGRESS.md](docs/plan/PROGRESS.md), and make one Conventional Commit that
   references the task, for example `feat(cli): add iace version (T-0003)`.
5. Push and open a pull request from the template. `main` only changes through pull requests
   that pass CI (`ci-ok`) and are up to date; a ruleset enforces this for everyone. Details:
   [docs/ci/branch-workflow.md](docs/ci/branch-workflow.md).

## Ground rules
- Never run Terraform, providers or modules from scanned code ([ADR 0003](docs/adr/0003-analyze-terraform-statically-never-execute-it.md)).
- Errors fail closed: policy, parse or config errors exit 2, never a silent pass.
- Tests never touch the network. Fixtures use obviously fake values, and secrets are never committed.
- Never weaken a gate, skip a test or lower a threshold to get green.
- Owner decisions are D-xx entries in the backlog; design decisions are [ADRs](docs/adr/).

## The development loop
Most work is done by an automated loop (`/iace-loop` in Claude Code) that takes one backlog task
per iteration through exactly these steps. Its standards live in the `.claude/skills/iace-*`
skills, and hooks in `.claude/settings.json` enforce the hard limits. Changes to `.claude/` and
`CLAUDE.md` (the harness) need the owner's approval.
