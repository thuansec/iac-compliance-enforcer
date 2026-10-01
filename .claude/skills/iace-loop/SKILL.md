---
name: iace-loop
description: Drive development of iac-compliance-enforcer (iace), the Go + OPA Terraform security-compliance scanner, one backlog task per iteration — orient, pick the next ready task, implement it test-first, pass the quality gates, record progress and commit. Use this whenever asked to continue, resume or advance work on iace, "work on the next task", run the build loop (for example `/loop /iace-loop`), bootstrap the repository, show loop status, or add, split, re-order or unblock backlog tasks.
argument-hint: "[bootstrap | status | plan | T-0000]"
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py *)
---

# iace development loop

Each invocation is **one iteration**: finish exactly one backlog task, leave `main` green,
record what happened, then stop. Everything the next iteration needs lives in files, never in
conversation memory, because the loop may run unattended, get compacted, or restart in a new session.

## Current state

!`python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py --brief`

If the block above is empty or shows an error, run
`python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py --brief` yourself before doing anything else.

## Arguments

Received: `$ARGUMENTS` (empty means a normal iteration)

- empty: run one normal iteration (below).
- `bootstrap`: first run only. Follow [references/bootstrap.md](references/bootstrap.md).
- `status`: report the state block plus blockers and open decisions. Change nothing.
- `plan`: groom the backlog (split oversized tasks, add tasks discovered during work, re-order
  within a milestone) using [references/backlog-format.md](references/backlog-format.md). No code changes.
- `T-xxxx`: work on that task (it must be ready or already in progress).

If `docs/plan/BACKLOG.md` does not exist, the repository is not bootstrapped. Run bootstrap first.

## Ground rules

These exist because nobody is watching each iteration. A violation can silently damage the
project or reach outside it.

1. **One task, small diff.** If the task cannot be finished in one iteration (rule of thumb: more
   than ~400 changed lines, or it touches more than one component boundary), split it in the
   backlog first and do the first slice.
2. **Never ask the user mid-iteration.** If a decision is genuinely the owner's (license, naming,
   paid services, key custody, anything outward-facing), add it to *Decisions needed* in
   `BACKLOG.md`, mark the task `[!]` with `blocked: needs-human — <question>`, and pick another ready task.
3. **Stay inside the repository.** No `sudo`, no global installs, no edits outside the repo.
   Pinned dev tools come from `tools/go.mod` (`go tool -modfile=tools/go.mod …`).
4. **Respect the loop settings** in `BACKLOG.md`. With the defaults, never `git push`, open PRs,
   create tags or releases, change GitHub settings, or make live paid API calls (Anthropic or
   others). The loop commits locally, and a human publishes.
5. **Never weaken a gate to get green.** That means no deleting or skipping tests, no lowering
   thresholds, no `//nolint` without a reason, and no `--no-verify`. If a gate itself is wrong,
   fix it in its own task and explain why.
6. **Never execute code from scanned Terraform** (`terraform init/plan`, providers, modules) and
   never put real secrets in fixtures or commands. See the `iace-security` skill.
7. **Never discard uncommitted work you did not create in this iteration.** A dirty tree means an
   earlier iteration was interrupted (see Orient).
8. **Hooks are hard limits.** `.claude/hooks/` blocks secrets in commands, pushes (unless allowed),
   destructive git commands, privilege escalation and commits the gates did not check. When a
   hook blocks you, don't retry with other syntax or a wrapper script. Fix the cause, or record a
   blocker if a human must act.

## The iteration

### 1. Orient
- Read `CLAUDE.md`, the state block, the selected task, and the last 2–3 entries of `docs/plan/PROGRESS.md`.
- `git status`: if the tree is dirty and an `[~]` task exists whose scope matches the diff, resume that
  task. If the dirty changes match nothing, stop. Record a `needs-human` blocker describing the
  diff and do not touch it.

### 2. Select
- Resume the `[~]` task if there is one. Otherwise take the argument task, or else the state
  block's *next ready* task: the first `[ ]` task, in file order, inside an `active` milestone,
  whose dependencies are all `[x]`.
- No ready task:
  - Milestone complete → do the milestone wrap-up (step 8).
  - Everything left is blocked or awaiting approval → report and end the loop (step 9).

### 3. Plan
- Mark the task `[~]` and increment `attempts`.
- Load the skills named in the task's `skills:` line. Always load `iace-architecture`
  when you touch contracts (the input document, findings, config, CLI).
- Write a 3–6 line plan in your working notes covering files to touch, tests that prove each
  acceptance bullet, and risks. If the plan reveals the task is too big or wrongly scoped,
  split or rewrite it in the backlog now.

### 4. Test first
Write the tests that encode the acceptance criteria and run them to watch them fail for the
right reason (`iace-testing`). A test that passes before the change proves nothing.

### 5. Implement
Write the minimum code that makes the tests pass, following `iace-go-standards`, `iace-security`
and the component skill. If a contract must change, update its reference document and add an
ADR in the same commit (`iace-architecture`).

### 6. Verify
- While iterating: `bash ${CLAUDE_PROJECT_DIR}/.claude/skills/iace-quality-gates/scripts/gates.sh quick`
- When the change is complete: walk the self-review checklist in `iace-quality-gates` against
  `git diff`, then run `bash ${CLAUDE_PROJECT_DIR}/.claude/skills/iace-quality-gates/scripts/gates.sh full`.
  It must pass, and on success it stamps the exact tree (`.cache/gates/full.pass`).
- **Independent review** for any iteration that changes code, tests, policies, workflows or
  hooks: delegate to the `iace-reviewer` subagent with the task ID, its acceptance criteria and a
  one-paragraph summary of the change. On `CHANGES_REQUIRED`, fix the blocker and major findings
  and run `gates.sh full` again. Re-review only if the fixes changed behaviour. Record minor
  findings as follow-up tasks. Skip the review for docs- or plan-only iterations.
- If you cannot get green within this iteration, go to *Failure handling*.

### 7. Record and commit
- Mark the task `[x]` and add a `result:` line (one sentence plus any follow-ups). Add newly
  discovered work as new tasks rather than widening this one.
- Append a PROGRESS entry (see the *Progress log* section of [references/backlog-format.md](references/backlog-format.md)).
- Make one commit containing the code, tests, docs, BACKLOG and PROGRESS changes, using a
  Conventional Commit that references the task, for example
  `feat(engine): evaluate rule packages with one prepared query (T-0203)`.
- The guard hook allows `git commit` only if the gates stamp matches the tree. After `gates.sh
  full`, change nothing except `docs/plan/BACKLOG.md` and `docs/plan/PROGRESS.md`. Any other edit
  means running the full gates again.

### 8. Milestone wrap-up
When the last task of a milestone is `[x]`:
- Append a milestone summary to PROGRESS: what now works, how to try it (commands), known gaps
  and the follow-up tasks that track them.
- Set the milestone to `done`. Then, if `pause_at_milestone_end: yes`, set the next milestone
  to `awaiting-approval` and end the loop. The human reviews and flips it to `active`.
  Otherwise set the next milestone to `active`.

### 9. Loop control
- **Under `/loop`:** if a ready task remains, schedule the next iteration soon (about 60–120 s;
  work is ready, so there is nothing to wait for). End the loop instead when there are no ready
  tasks, a milestone pause is reached, every remaining task is blocked, or three consecutive
  iterations failed.
- **Headless**, via `scripts/run-loop.sh`: one fresh `claude -p "/iace-loop"` process per iteration.
  This is the recommended way to run long unattended stretches, because a single session
  degrades as its context fills. End every headless iteration with a final line
  `LOOP_STATUS: continue|paused|done|blocked`; the runner stops on anything but `continue`.
- Finish each iteration with a short report: task, outcome, commit hash, and what comes next.

## Failure handling
- Gates fail and you cannot fix them this iteration: never commit a red tree. Save the attempt with
  `git stash push -u -m "T-xxxx attempt N: <reason>"`, leave the task `[~]`, and record the
  attempt (with the stash name and what you learned) in PROGRESS. Stashes are kept for a human
  (`stash drop`/`clear` is blocked).
- When `attempts` reaches `max_attempts_per_task`, mark the task `[!]` with `blocked: <reason>`
  (and `needs-human` if applicable), then move on.
- Environment problems (missing toolchain, auth, network) block the task as `needs-human` with
  the exact command the human should run.

## References
- [references/backlog-format.md](references/backlog-format.md): BACKLOG and PROGRESS formats, task anatomy, grooming rules.
- [references/roadmap.md](references/roadmap.md): seed backlog (milestones M0–M11); bootstrap copies it to `docs/plan/BACKLOG.md`.
- [references/bootstrap.md](references/bootstrap.md): first-run setup, the git remote, and the `CLAUDE.md` template.
- `scripts/loop_status.py [--brief|--json]`: parses BACKLOG and git state and computes the next ready task.
- `scripts/run-loop.sh [--max-iterations N] [--budget-usd X] ...`: fresh-context runner (`--help`).
- `.claude/agents/iace-reviewer.md`: the independent reviewer used in step 6.
