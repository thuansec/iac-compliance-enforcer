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
