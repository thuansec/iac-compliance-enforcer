# Bootstrap (first run)

Run this once, when `docs/plan/BACKLOG.md` does not exist. It is task T-0001. Work from the
project root: the directory that contains `.claude/skills/iace-*`.

## 1. Preconditions
- `gh auth status` succeeds **and** `git ls-remote https://github.com/thuansec/iac-compliance-enforcer.git`
  lists `refs/heads/main`. The repo is private, and git uses gh's credentials via
  `gh auth setup-git`. If either fails, stop and ask the human to fix access. This is the one
  bootstrap step that may stop and wait, because nothing else can proceed without it.
  - Not logged in: `! gh auth login` then `! gh auth setup-git`.
  - 403/404 with a fine-grained token means the token doesn't include this repository. On
    GitHub → Settings → Developer settings → Fine-grained tokens, edit the token: add
    `iac-compliance-enforcer` under *Repository access* and grant **Contents: read & write**,
    **Workflows: read & write** (needed to push `.github/workflows/*`), **Pull requests: read &
    write**, and optionally **Actions: read** and **Code scanning alerts: read**. Metadata: read is
    automatic. Add **Administration: read & write** only to apply rulesets from the CLI.
  - Record the token expiry (`gh api -i /user | grep -i token-expiration`) in the PROGRESS
    entry. An expired token stops the human's pushes and the loop's `gh api` lookups.
- Note which tools are missing (`go`, `opa`, `terraform`, `jq`) in the PROGRESS entry. Missing
  Go does not block bootstrap; it blocks T-0002.

## 2. Wire the working copy to GitHub
The upstream repository is `https://github.com/thuansec/iac-compliance-enforcer.git`. It holds
`README.md` and a Go `.gitignore`.

```bash
git init -b main                      # skip if already a git repository
git remote add origin https://github.com/thuansec/iac-compliance-enforcer.git   # skip if present
git pull origin main                  # fast-forwards the empty branch; untracked .claude/ is kept
git branch --set-upstream-to=origin/main main
```

If `origin` exists but points elsewhere, or local history has diverged from `origin/main`,
stop with a `needs-human` blocker. Never force anything.

Append to `.gitignore` (keep the upstream entries):
```
# iace
/bin/
/dist/
/.cache/
.claude/settings.local.json
```

## 3. Create the plan files
- `docs/plan/BACKLOG.md`: copy [roadmap.md](roadmap.md) verbatim, then mark T-0001 `[x]`
  with a `result:` line.
- `docs/plan/PROGRESS.md`:
  ```markdown
  # iace progress log

  Append-only. One entry per loop iteration; newest last. Format: .claude/skills/iace-loop/references/backlog-format.md
  ```
  Then add the first entry (`T-0001 · done`), which records the tool versions found or missing.

## 4. Create CLAUDE.md
Keep it short. It is loaded into every session, and the skills hold the detail.

```markdown
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
- `make tools` installs the pinned dev tools (one module per tool, tools/<tool>/go.mod).
- `make fmt`, `make lint`, `make test`, `make policy-test`, `make vuln`, `make ci`
- Gates: `bash .claude/skills/iace-quality-gates/scripts/gates.sh quick|full`

## Non-negotiables
- Never execute Terraform, providers, or module code from scanned repositories.
- Errors fail closed: policy/parse/config errors exit 2, never a silent pass.
- Tests never touch the network; no live AI calls unless BACKLOG loop settings allow it.
- Don't weaken gates or tests to get green. Conventional commits that reference task IDs.
- Never commit secrets. Fixtures use obviously fake values.
```

## 5. Commit (do not push)
```bash
git add .gitignore CLAUDE.md docs/plan .claude
git commit -m "chore: bootstrap loop backlog, project memory and skills (T-0001)"
```

Confirm `git status` is clean and `python3 .claude/skills/iace-loop/scripts/loop_status.py --brief`
shows T-0002 as next. Then finish the iteration report. The next iteration starts T-0002.
