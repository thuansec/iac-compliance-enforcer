---
name: iace-loop
description: Drive development of iac-compliance-enforcer (iace), the Go + OPA Terraform security-compliance scanner, one backlog task per iteration — orient, pick the next ready task, implement it test-first on a feature branch, pass the quality gates, open a pull request, wait for CI, and merge only when it is green, up to date and conflict-free. Use this whenever asked to continue, resume or advance work on iace, "work on the next task", run the build loop (for example `/loop /iace-loop`), bootstrap the repository, show loop status, follow up an open loop pull request, or add, split, re-order or unblock backlog tasks.
argument-hint: "[bootstrap | status | plan | T-0000]"
allowed-tools: Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py *), Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/ci_state.py *)
---

# iace development loop

Each invocation is **one iteration**: move exactly one backlog task forward, from a feature branch
through a pull request into `main`, record what happened, then stop. Everything the next
iteration needs lives in files, git and GitHub, never in conversation memory, because the loop may
run unattended, get compacted, or restart in a new session.

## Current state

!`python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py --brief`

If the block above is empty or shows an error, run
`python3 ${CLAUDE_SKILL_DIR}/scripts/loop_status.py --brief` yourself before doing anything else.

## Arguments

Received: `$ARGUMENTS` (empty means a normal iteration)

- empty: run one normal iteration (below).
- `bootstrap`: first run only. Follow [references/bootstrap.md](references/bootstrap.md).
- `status`: report the state block plus blockers and open decisions. Change nothing.
- `plan`: groom the backlog (split oversized tasks, add discovered tasks, re-order within a
  milestone) using [references/backlog-format.md](references/backlog-format.md). No code changes;
  the grooming still lands through a `chore/` branch and PR.
- `T-xxxx`: work on that task (it must be ready or already in progress).

If `docs/plan/BACKLOG.md` does not exist, the repository is not bootstrapped. Run bootstrap first.

## Loop policy
`.claude/loop-policy.json` holds what the loop may do outside the working tree:
`push_feature_branches`, `open_pull_requests`, `merge_pull_requests`, `merge_method` (squash),
`auto_merge` (only with a server-side ruleset), `required_check` (`ci-ok`) and `live_api_calls`.
It is a harness file: the loop reads it and never edits it. The guard hook enforces it.
Background: [docs/ci/branch-workflow.md](../../../docs/ci/branch-workflow.md).

## Ground rules

These exist because nobody is watching each iteration. A violation can silently damage the
project or reach outside it.

1. **One task, one branch, one PR, small diff.** Only one loop PR may be open at a time. If a
   task can't be finished in one iteration (rule of thumb: more than ~400 changed lines, or it
   crosses a component boundary), split it in the backlog first and do the first slice.
2. **`main` only changes through merged pull requests.** Never commit or push to it. The guard
   blocks both.
3. **Never ask the user mid-iteration.** If a decision is genuinely the owner's (license, naming,
   paid services, key custody, anything outward-facing), add it to *Decisions needed* in
   `BACKLOG.md`, mark the task `[!]` with `blocked: needs-human — <question>`, and pick another ready task.
4. **Stay inside the repository and the policy.** No `sudo`, no global installs, no edits outside
   the repo, nothing the loop policy doesn't allow, and no live paid API calls unless
   `live_api_calls` is true. Pinned dev tools come from `tools/<tool>/go.mod`.
5. **Never touch the harness** (`.claude/**`, `CLAUDE.md`). Changes there need a human: the
   guard asks, and unattended runs deny.
6. **Never weaken a gate to get green.** That means no deleting or skipping tests, no lowering
   thresholds, no `//nolint` without a reason, and no `--no-verify`. If a gate is wrong, record a blocker.
7. **Never execute code from scanned Terraform** (`terraform init/plan`, providers, modules), and
   never put real secrets in fixtures or commands. See the `iace-security` skill.
8. **Never discard work you did not create in this iteration.** A dirty tree means an earlier
   iteration was interrupted (see Orient).
9. **Hooks are hard limits.** When a hook blocks you, don't retry with other syntax or a wrapper
   script. Fix the cause, or record a blocker if a human must act.

## The iteration

### 1. Orient
- Read `CLAUDE.md`, the state block, and the last 2–3 entries of `docs/plan/PROGRESS.md`.
- `git fetch origin --prune`.
- **Verdict `pr-open`** (an open loop PR exists): go to step 10, *PR follow-up*. Don't start new work.
- On a feature branch with uncommitted work matching the `[~]` task: resume it. Uncommitted
  changes that match nothing: stop and record a `needs-human` blocker. Don't touch them.
- Otherwise: `git switch main && git pull --ff-only`, so `main` equals `origin/main`.

### 2. Select
- Resume the `[~]` task if there is one. Otherwise take the argument task, or else the state
  block's *next ready* task: the first `[ ]` task, in file order, inside an `active` milestone,
  whose dependencies are all `[x]`.
- No ready task: milestone complete → step 11. Everything left blocked or awaiting approval →
  report and end the loop (step 12).

### 3. Branch and plan
- From the up-to-date `main`: `git switch -c <type>/T-xxxx-<slug>`. The type is the Conventional
  Commit type (`feat`, `fix`, `docs`, `test`, `chore`, `ci`, `refactor`); the slug is 2–5 words.
- Mark the task `[~]` and increment `attempts`. Load the skills on its `skills:` line, and
  `iace-architecture` whenever contracts change.
- Write a 3–6 line plan covering files, the tests that prove each acceptance bullet, and risks.
  Split or rewrite the task now if it is too big.

### 4. Test first
Write the tests that encode the acceptance criteria and run them to watch them fail for the
right reason (`iace-testing`). A test that passes before the change proves nothing.

### 5. Implement
Write the minimum code that makes the tests pass, following `iace-go-standards`, `iace-security`
and the component skill. If a contract changes, update its reference doc and add an ADR in the same branch.

### 6. Verify
- While iterating: `bash ${CLAUDE_PROJECT_DIR}/.claude/skills/iace-quality-gates/scripts/gates.sh quick`
- When the change is complete: walk the self-review checklist in `iace-quality-gates`, then run
  `bash ${CLAUDE_PROJECT_DIR}/.claude/skills/iace-quality-gates/scripts/gates.sh full`. It must
  pass, and it stamps the exact content (`.cache/gates/full.pass`).
- **Independent review** for any change to code, tests, policies, workflows or hooks: delegate to
  the `iace-reviewer` subagent with the task ID, its acceptance criteria and a one-paragraph
  summary. On `CHANGES_REQUIRED`, fix the blocker and major findings and run `gates.sh full` again.
  Record minor findings as follow-up tasks. Skip the review for docs- or plan-only changes.

### 7. Record and commit (on the feature branch)
- Mark the task `[x]` with a `result:` line, and append a PROGRESS entry with What, Files,
  Evidence, Review and Next (format in [references/backlog-format.md](references/backlog-format.md)).
- Commit once with a Conventional Commit that references the task, for example
  `feat(engine): evaluate rule packages with one prepared query (T-0203)`.
- The guard allows the commit only on a feature branch, and only if the gates stamp matches the
  content. After `gates.sh full`, change nothing except BACKLOG.md and PROGRESS.md.

### 8. Publish
- `git push -u origin HEAD`. The guard requires a clean tree and a matching stamp, and pushes
  only the checked-out branch, never `main`.
- `gh pr create --base main --title "<commit subject>" --body-file <file>`. The body follows
  `.github/pull_request_template.md`: task, changes, acceptance with proof, evidence (gates,
  reviewer verdict), risk.
- If the policy doesn't allow pushing or opening PRs, stop here with `LOOP_STATUS: paused` and
  say what the human should do.

### 9. CI, then merge
- Wait for CI on the pushed head (give the Bash call a 600000 ms timeout):
  `python3 ${CLAUDE_SKILL_DIR}/scripts/ci_state.py --wait`. It polls the GitHub Actions API for up
  to 9 minutes and stops early on the first failed job. Don't use `gh pr checks`, `gh run watch` or
  plain `gh run view <id>`: the token is fine-grained, which can't read checks, so they fail with HTTP 403.
  Exit codes: 0 green · 1 red · 2 still running · 3 unknown (gh, network or token).
- **Green (0)**: read `headRefOid`, `mergeable` and `mergeStateStatus` with `gh pr view <n> --json`,
  then `gh pr merge <n> --squash --delete-branch --match-head-commit <headRefOid>`. The guard
  re-verifies: open, not a draft, conflict-free, up to date with `main`, the latest run of every
  workflow passed, `ci-ok` included. Then `git switch main && git pull --ff-only`.
  If `merge_pull_requests` is false, leave the PR for a human and end with `LOOP_STATUS: paused`.
- **Red (1)**: the output names the failed jobs and the log command
  (`gh run view <run-id> --log-failed`). Fix on the branch, run the gates, commit, push, and wait
  again. Each red round counts as an attempt.
- **Behind `main` or conflicting**: `git merge --no-edit origin/main` into the branch (never rebase
  a pushed branch: that needs a force push, which is blocked). Resolve conflicts, then run
  `gates.sh full`, commit and push.
- **Still running (2)**: run the wait once more. If CI is still running after that, end the
  iteration with `LOOP_STATUS: waiting`; the next iteration resumes at step 10.
- **Unknown (3)**: run it once more. If it fails again, record the error as a `needs-human`
  blocker in PROGRESS and end with `LOOP_STATUS: blocked`.

### 10. PR follow-up (verdict `pr-open`)
`git fetch origin && git switch <headRefName>`, read that branch's task and PROGRESS entries,
then act on the PR's state exactly as in step 9: wait, fix, update or merge. When the task's
`attempts` reach `max_attempts_per_task` with CI still red, stop with `LOOP_STATUS: blocked` and a
`needs-human` note in PROGRESS on the branch (pushed). The open PR is the human's signal.

### 11. Milestone wrap-up
When the last task of a milestone is `[x]` on `main`, use a `chore/M<n>-wrap-up` branch and PR:
- Append a milestone summary to PROGRESS: what now works, how to try it, known gaps with their
  follow-up tasks.
- Set the milestone to `done`. If `pause_at_milestone_end: yes`, set the next milestone to
  `awaiting-approval`; otherwise set it to `active`.
- Merge the PR as in step 9, then end the loop if paused. The human reviews and flips the status.

### 12. Loop control
- End every iteration with a short report (task, outcome, PR number, merge commit, what's next)
  and a final line `LOOP_STATUS: continue|waiting|paused|done|blocked`.
- **Headless**, via `scripts/run-loop.sh`: one fresh `claude -p "/iace-loop"` process per
  iteration, recommended for long runs. `waiting` makes the runner back off and retry. Anything
  other than `continue`/`waiting` stops it.
- **Under `/loop`**: schedule the next iteration in about 60–120 s, or about 300 s when
  `waiting`. End the loop on `paused`, `done`, `blocked`, or three consecutive failed iterations.

## Failure handling
- Gates red and not fixable this iteration: never commit a red tree. Save the attempt with
  `git stash push -u -m "T-xxxx attempt N: <reason>"`, leave the task `[~]`, and record the attempt
  (stash name, what you learned) in PROGRESS. Stashes are kept for a human (`drop`/`clear` is blocked).
- `attempts` at `max_attempts_per_task`: mark the task `[!]` with `blocked: <reason>`
  (`needs-human` if applicable) through a PR, or leave the open PR as the signal (step 10).
- Environment problems (missing toolchain, auth, network, Actions disabled) block the task as
  `needs-human` with the exact command the human should run.

## References
- [references/backlog-format.md](references/backlog-format.md): BACKLOG and PROGRESS formats, task anatomy, grooming rules.
- [references/roadmap.md](references/roadmap.md): seed backlog (milestones M0–M11); bootstrap copies it to `docs/plan/BACKLOG.md`.
- [references/bootstrap.md](references/bootstrap.md): first-run setup, the git remote, and the `CLAUDE.md` template.
- `scripts/loop_status.py [--brief|--json] [--no-network]`: backlog, policy, git and open PRs; computes the next step.
- `scripts/ci_state.py [--sha SHA] [--wait] [--json]`: CI verdict for a commit from the Actions API, using the merge gate's rule (step 9).
- `scripts/run-loop.sh [--max-iterations N] [--budget-usd X] ...`: fresh-context runner (`--help`).
- `.claude/agents/iace-reviewer.md`: the independent reviewer used in step 6.
- `docs/ci/branch-workflow.md`, `.github/workflows/ci.yml`: the merge gate, CI and the optional GitHub ruleset.
