# iac-compliance-enforcer (iace)

Terraform security-compliance scanner in Go. It parses Terraform (static HCL by default, or plan
JSON), evaluates Rego policies with embedded OPA, applies per-repo policy config and exceptions,
reports text/JSON/SARIF/JUnit/Markdown, gates pull requests, and can suggest AI-generated fixes
that it then verifies.

## How work happens here
- Development runs through the `iace-loop` skill: one task per iteration from docs/plan/BACKLOG.md,
  with history in docs/plan/PROGRESS.md and decisions in docs/adr/.
- Standards live in the `.claude/skills/iace-*` skills. Load the ones for the area you touch.

## Commands
- `make tools` installs the pinned dev tools (tools/go.mod).
- `make fmt`, `make lint`, `make test`, `make policy-test`, `make vuln`, `make ci`
- Gates: `bash .claude/skills/iace-quality-gates/scripts/gates.sh quick|full`

## Harness
- Every change reaches `main` through a feature branch and a PR that passed CI (`ci-ok`), is up
  to date and has no conflicts. See docs/ci/branch-workflow.md; permissions are in `.claude/loop-policy.json`.
- Hooks in `.claude/settings.json` are hard limits. They block secrets in commands, commits or
  pushes to `main`, unverified commits, pushes and merges, and destructive git commands, and they
  ask a human before any harness edit. When blocked, fix the cause or record a blocker. Never
  route around a hook.
- Unattended runs: `.claude/skills/iace-loop/scripts/run-loop.sh` (fresh context per iteration).
  Stop gracefully with `touch .cache/loop/STOP`.
- After changing anything in `.claude/hooks/` or `.claude/settings.json`, run `.claude/hooks/tests/run.sh`.

## Non-negotiables
- Never execute Terraform, providers, or module code from scanned repositories.
- Errors fail closed: policy/parse/config errors exit 2, never a silent pass.
- Tests never touch the network; no live AI calls unless BACKLOG loop settings allow it.
- Don't weaken gates or tests to get green. Conventional commits that reference task IDs.
- Never commit secrets. Fixtures use obviously fake values.
