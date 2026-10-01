# Backlog and progress formats

`scripts/loop_status.py` parses these files, so keep the exact markers. Humans edit them too,
so keep them readable.

## docs/plan/BACKLOG.md

```markdown
# iace backlog

## Loop settings
Permissions (push, pull requests, merge, live API calls) live in `.claude/loop-policy.json`.
- pause_at_milestone_end: yes
- max_attempts_per_task: 3

## Decisions needed
- D-01 · License for the repository. Default until decided: none (release tasks wait). Owner: @thuansec

## M0 · Foundations — status: active
Goal: one sentence on what is true when the milestone is done.

- [ ] T-0002 · Verify toolchain and pin dev tools
  - skills: iace-go-standards, iace-quality-gates
  - depends: T-0001
  - accept:
    - observable, checkable outcome 1
    - observable, checkable outcome 2
  - attempts: 0
```

### Settings
| key | meaning | default |
|---|---|---|
| `pause_at_milestone_end` | stop and wait for human approval between milestones | `yes` |
| `max_attempts_per_task` | failed attempts before a task is marked blocked | `3` |

Only a human changes settings. The loop reads them and never edits them.

Anything that reaches outside the working tree is a *permission* and lives in the harness file
`.claude/loop-policy.json`. The guard hook enforces it, and the loop can't edit it.

| policy key | meaning | default |
|---|---|---|
| `git_workflow` | `pull-request`: feature branch, PR, CI, merge; never commit to `default_branch` | `pull-request` |
| `push_feature_branches` | push the checked-out feature branch after the full gates passed | `true` |
| `open_pull_requests` | `gh pr create` | `true` |
| `merge_pull_requests` | `gh pr merge --squash --match-head-commit` once the PR is green, up to date and conflict-free | `true` |
| `auto_merge` | `gh pr merge --auto`; only with the server-side ruleset (docs/ci/branch-workflow.md) | `false` |
| `required_check` | the CI check that must pass before merging | `ci-ok` |
| `live_api_calls` | tests or tasks may call paid external APIs (Anthropic) | `false` |

### Milestone header
`## M<n> · <title> — status: <status>` where status is one of
`planned | active | awaiting-approval | done`. Several milestones may be `active` at once if
the human wants parallel tracks. The loop works through active milestones in file order.

### Task line and fields
`- [<mark>] T-<4 digits>[a-z]? · <imperative title>`

| mark | meaning |
|---|---|
| `[ ]` | todo |
| `[~]` | in progress (at most one at a time) |
| `[x]` | done |
| `[!]` | blocked; the task must have a `blocked:` field |

Field lines are indented two spaces with a dash:
- `skills:` the skills to load (comma-separated).
- `depends:` task IDs that must be `[x]`, or `—` for none.
- `accept:` acceptance criteria as nested bullets. Each one must be checkable by a command, a
  test, or by inspecting a file. "Works well" is not acceptance.
- `attempts:` integer, incremented when a task is started or resumed.
- `blocked:` reason. Prefix it with `needs-human —` when only the owner can unblock it.
- `result:` one sentence written when the task is done (plus follow-up task IDs).

Task IDs: `T-<milestone 2 digits><seq 2 digits>`, e.g. `T-0305` is the 5th task of M3. Split
tasks take letter suffixes (`T-0305a`, `T-0305b`), and the original task becomes the first slice.

### Grooming rules (`plan` mode)
- Split by observable behaviour, not by layer. "Parse .tf.json files" is a good slice; "write
  the structs" is not.
- Every task leaves `main` releasable: tests pass and nothing is half-wired behind dead code.
- New work discovered mid-task becomes a new `[ ]` task in the right milestone with `depends:`
  set. It does not widen the current task.
- Never delete a done task. Mark obsolete ones `[x]` with `result: superseded by T-…`.
- Keep acceptance criteria concrete: name the command, the file, the exit code, the test.

## docs/plan/PROGRESS.md

### Progress log
Append-only, newest entry last. One entry per iteration, including failed attempts:

```markdown
### 2026-10-02 · T-0103 · done
- What: parse .tf and .tf.json into raw blocks with source ranges.
- Files: internal/terraform/parse.go, parse_test.go, testdata/terraform/parse/*.
- Evidence: `gates.sh full` PASS; FuzzParse 60s clean; commit 1a2b3c4.
- Review: iace-reviewer APPROVE (1 minor finding, tracked as T-0110).
- Decisions: kept override files as warnings (ADR 0005).
- Next: T-0104.
```

`Files` and `Review` make each entry a handoff for the next fresh-context iteration: it can
orient from the log without re-reading the code. `Review` is `skipped (docs-only)` when no review ran.

Outcome is one of `done | attempt-failed | blocked | split | groomed`. For failed attempts,
record the stash name and what you learned, so the next attempt starts smarter.

### Milestone summary
```markdown
## Milestone M1 complete · 2026-10-05
- Works now: `iace inspect ./examples/aws-basic --json` prints the normalized input document.
- Try it: `go run ./cmd/iace inspect testdata/terraform/e2e/aws-basic`
- Known gaps: remote modules unresolved without `.terraform/modules` (T-0906).
```
