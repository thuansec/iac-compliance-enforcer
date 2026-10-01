---
paths:
  - ".claude/**"
  - "CLAUDE.md"
---

# Changing the harness (skills, hooks, agents, settings)

- Hooks are guarantees, so changes must keep them at least as strict. After editing anything in
  `.claude/hooks/` or `.claude/settings.json`, run `.claude/hooks/tests/run.sh` and add a test
  case for the new behaviour.
- Never weaken a guard to get past a block. If a guard is wrong, fix it with a test that shows why.
- Keep skill descriptions accurate: they decide when a skill loads. Run `/doctor prompt-audit .claude`
  to find stale or conflicting instructions.
- Skills, hooks, settings and agents reload live. Rules and CLAUDE.md load at session start or after `/compact`.
