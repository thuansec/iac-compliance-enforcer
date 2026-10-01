# iace harness: skills, hooks, agents, rules

The Claude Code setup that builds **iac-compliance-enforcer (`iace`)**, a Go and OPA scanner
for Terraform security compliance on AWS and Azure, through an autonomous development loop.
Claude Code loads everything here automatically. This README is for humans.

## How the loop runs
Every task goes feature branch → PR → CI (`ci-ok`) → merge only when green, up to date and
conflict-free (`docs/ci/branch-workflow.md`). Only one loop PR is open at a time.
```
run-loop.sh  (fresh `claude -p "/iace-loop"` per iteration)   or   /loop /iace-loop  (one session)
   │
   ▼
iace-loop: orient (open loop PR? finish it first) → select task (docs/plan/BACKLOG.md)
           → git switch -c feat/T-xxxx-slug → plan → test first → implement → self-review
           → gates.sh full (stamps the content) → iace-reviewer subagent → record → commit → push
           → gh pr create → CI (gates + ci-ok) → merge gate → squash into main
   │          │                                       │
   │          └─ skills on the task + .claude/rules/  └─ guard hook: commit and push only stamped content,
   ▼                                                     merge only green, up-to-date, conflict-free PRs
stops at each milestone for your approval (pause_at_milestone_end: yes)
```

## Layers
| layer | where | job |
|---|---|---|
| Instructions | `CLAUDE.md` | project facts and non-negotiables, loaded every session |
| Knowledge | `.claude/skills/iace-*` | how to do each part well, loaded when relevant |
| Rules | `.claude/rules/*.md` | short constraints injected when Claude reads matching files (policies, loader, workflows, AI, harness) |
| Guarantees | `.claude/hooks/` + `.claude/settings.json` | deterministic blocks that run no matter what the model decides |
| Second opinion | `.claude/agents/iace-reviewer.md` | read-only independent review of each code-changing iteration |
| State | `docs/plan/BACKLOG.md`, `PROGRESS.md`, git | everything an iteration needs, on disk |

### Hooks (tested by `.claude/hooks/tests/run.sh`, 173 cases; also run by the gates and CI)
- `block-secrets.sh` (PreToolUse Bash) blocks credential formats in commands. Fails closed without `jq`.
- `guard-loop.py` (PreToolUse Bash, Write, Edit) enforces `.claude/loop-policy.json`:
  - branch workflow: no commits or pushes to `main`; a feature branch is pushed only after the
    full gates passed on its exact content; force pushes are always blocked;
  - merge gate: `gh pr merge --squash --match-head-commit` only when the PR is open, not a draft,
    conflict-free, up to date with `main`, and every check passed (`ci-ok` included);
  - `reset --hard`, `clean -f`, whole-tree discards, stash drop and `branch -D`;
  - `sudo`, downloads piped into a shell, terraform apply/destroy, other GitHub writes, `gh auth token`;
  - commits whose content the full gates did not check;
  - **asks you** before any edit to the harness (`.claude/**`, `CLAUDE.md`). Unattended runs can't approve, so they can't change their own rules.
- `format-file.sh` (PostToolUse Write|Edit) runs gofumpt/goimports (or gofmt), `opa fmt` and `terraform fmt`.
- `permissions.deny` repeats the most destructive commands. `permissions.allow` pre-approves
  routine build, test and lint commands, so unattended runs don't stall.

You can always run something yourself with the `!` prefix (e.g. `! git push`). It doesn't go through hooks.

## Skills
| skill | role | key bundled files |
|---|---|---|
| `iace-loop` | entry point: one task per iteration, bootstrap, backlog rules, stop conditions | `references/roadmap.md` (12 milestones, 92 tasks), `scripts/loop_status.py`, `scripts/run-loop.sh` |
| `iace-architecture` | pipeline, package layout, contracts, exit codes, ADRs | `references/input-document.md` (Go→Rego contract), `findings-and-cli.md` |
| `iace-go-standards` | Go toolchain, idioms, errors, logging, deps and licenses | `assets/golangci.yml` (v2, verified) |
| `iace-terraform-parsing` | static HCL loading, evaluation, modules, plan JSON; never executes Terraform | `references/hcl-evaluation.md`, `plan-json.md` |
| `iace-opa-engine` | embedded OPA v1, restricted capabilities, prepared query, fail-closed decoding | `references/capabilities.md` |
| `iace-rego-policies` | writing and testing rules: unknowns, defaults, provider majors | `assets/policies/` (lib + template rule, tests, verified), `assets/regal-config.yaml` |
| `iace-cloud-controls` | AWS and Azure control catalog with verified defaults and mappings | `references/aws.md`, `azure.md`, `frameworks.md`, `scripts/provider_schema.sh` |
| `iace-repo-policy` | `.iace.yaml`, exceptions (owner/reason/expiry), org baseline, signed policy bundles | `references/config-schema.md`, `policy-supply-chain.md` |
| `iace-reporting` | text, JSON, SARIF (GitHub), JUnit, Markdown, annotations | `references/sarif.md` |
| `iace-ci-cd` | this repo's CI and releases, plus PR enforcement (Action, code scanning, rulesets) | `references/consumer-workflow.md`, `release.md` |
| `iace-ai-remediation` | opt-in AI fix suggestions, verified by re-scanning | `references/prompt-contract.md` |
| `iace-testing` | test-first, fixture harness, golden, testscript, fuzz, benchmarks | — |
| `iace-security` | trust boundaries, secure coding, supply chain, harness guardrails | `references/threat-model.md` |
| `iace-quality-gates` | definition of done, Makefile contract, commit gate | `scripts/gates.sh`, `scripts/tree-fingerprint.sh` |

## Changing the setup: what reloads when (Claude Code docs, checked 2026-10-01)
| you change | takes effect | you do |
|---|---|---|
| a skill's `SKILL.md` (edit, add or remove) | live within the session; content applies the **next time the skill is invoked** | nothing (re-invoke it, or `/clear` for a clean slate) |
| skill `references/`, `scripts/`, `assets/` | read when used | nothing |
| a brand-new top-level skills directory | not watched until reloaded | `/reload-skills` |
| `.claude/settings.json`: hooks, permissions | live (file watcher) | nothing; check with `/status`, browse with `/hooks`, errors via `claude doctor` |
| `env` in settings, `model`, `effortLevel` | session start | restart, or `/model` / `/effort` |
| hook scripts in `.claude/hooks/` | the next time the hook fires | run `.claude/hooks/tests/run.sh` |
| `.claude/agents/*.md` | live; but the **first** file in a new agents directory needs a restart | restart once |
| `CLAUDE.md`, `.claude/rules/*.md` | session start; CLAUDE.md is re-read after `/compact`; path rules load when matching files are read | `/clear` or restart |
| anything, under `run-loop.sh` | every iteration is a new process | nothing |

Audit instructions for stale or conflicting content with `/doctor prompt-audit .claude`.

## Running the loop
- Supervised, one session: `/loop /iace-loop`
- Unattended, fresh context per iteration (recommended for long runs):
  `.claude/skills/iace-loop/scripts/run-loop.sh --max-iterations 20 --budget-usd 30`
  (it uses `--permission-mode auto` by default; `--permission-mode acceptEdits` relies on
  `permissions.allow`). Watch with `tail -f .cache/loop/logs/*.jsonl`. Stop after the
  current iteration with `touch .cache/loop/STOP`.

## Verified while building this (2026-10-01)
- Rego templates: `opa fmt`, `opa check --strict` with restricted capabilities, `opa test` 18/18
  passing at 100% coverage (OPA 1.21.1), and `regal lint` clean (Regal 0.43.0). ES256 bundle
  signing round-trips.
- Provider defaults from aws 6.67.0, azurerm 4.81.0 and 5.7.0 docs. AWS Security Hub IDs from
  AWS's control reference.
- GitHub: `upload-sarif@v4`, the SARIF severity mapping and limits, permissions for private
  repos, code-scanning merge protection.
- Harness: 173 hook tests (branch, commit, push and merge gates with a fake `gh`, harness
  protection), a live guard block inside Claude Code, the runner exercised against
  a fake `claude` (stop on paused, failures, budget and STOP file), and tree-fingerprint
  sensitivity in 6 scenarios.
