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
- Hooks in `.claude/settings.json` are hard limits. They block secrets in commands, pushes
  (unless BACKLOG allows them), destructive git commands, and commits the full gates did not check.
  When blocked, fix the cause or record a blocker. Never route around a hook.
- Unattended runs: `.claude/skills/iace-loop/scripts/run-loop.sh` (fresh context per iteration).
  Stop gracefully with `touch .cache/loop/STOP`.
- After changing anything in `.claude/hooks/` or `.claude/settings.json`, run `.claude/hooks/tests/run.sh`.

## Non-negotiables
- Never execute Terraform, providers, or module code from scanned repositories.
- Errors fail closed: policy/parse/config errors exit 2, never a silent pass.
- Tests never touch the network; no live AI calls unless BACKLOG loop settings allow it.
- Don't weaken gates or tests to get green. Conventional commits that reference task IDs.
- Never commit secrets. Fixtures use obviously fake values.
