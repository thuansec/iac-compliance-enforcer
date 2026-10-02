# Branch and merge workflow

Every change reaches `main` through a pull request that passed CI, has no conflicts, and was
tested against the latest `main`.

```
main ──► git switch -c feat/T-0002-pin-tools ──► commits (full gates pass locally; commit gate)
     ──► git push -u origin HEAD (push gate) ──► gh pr create
     ──► CI: gates + ci-ok ──► behind or conflicting? merge origin/main into the branch, gates, push
     ──► green, up to date, mergeable ──► gh pr merge --squash --match-head-commit <sha> (merge gate)
     ──► main (one squash commit per task)
```

## Who enforces what
| layer | enforces | available |
|---|---|---|
| Guard hook (`.claude/hooks/guard-loop.py`) | Claude never commits or pushes to `main`; pushes only content the full gates passed; merges only open, non-draft, conflict-free, up-to-date PRs whose latest CI runs (including the `ci-ok` job) all passed; squash only; never `--admin` | now |
| CI (`.github/workflows/ci.yml`) | gates on every PR and on `main`, tested on the PR merged with its base | now (free on standard runners for public repositories) |
| GitHub ruleset (`docs/ci/main-ruleset.json`) | the same rules for **everyone**: PR required, `ci-ok` required, branch up to date (strict), no force push or deletion, squash only | available since the repository went public (2026-10-02, D-08); the owner applies it (step 2 below; status in docs/security/going-public.md) |

**Decision (2026-10-01, updated 2026-10-02): GitHub Free; the repository is public since
2026-10-02 (D-08).** Until the owner applies the ruleset, the merge gate is enforced by the guard
hook (for Claude) and CI (for every PR), and nothing on GitHub stops a human pushing to `main`, so
don't. Keep `auto_merge` false until the ruleset is active: without it, GitHub would auto-merge
without waiting for checks.

The loop's permissions (push branches, open PRs, merge, auto-merge) are set in
`.claude/loop-policy.json`. That is a harness file, so the loop cannot change them; edits ask a human.

## Reading CI with a fine-grained token
The `gh` login uses a fine-grained personal access token, which **cannot read checks or commit
statuses**. `gh pr checks`, the `statusCheckRollup` field, `gh run watch` (on a running run) and plain
`gh run view <id>` fail with *HTTP 403: Resource not accessible by personal access token*; the last two
fail because they fetch check-run annotations. The token's **Actions: read** permission does cover
workflow runs and jobs, so CI is read from there:

- the merge gate (guard) and `.claude/skills/iace-loop/scripts/ci_state.py` apply the same rule:
  the latest `pull_request` run of every workflow for the PR head passed, and so did the `ci-ok` job;
- the loop waits with `ci_state.py --wait` and reads failures with `gh run view <id> --log-failed`
  (that path skips annotations, so it works).

A classic token, or adding **Checks: read** where GitHub offers it, would make `gh pr checks` work
too. Nothing depends on it.

## One-time GitHub setup (run these yourself)
Each command needs a token with **Administration: read & write** on this repository. The loop never
runs them, because the guard blocks GitHub writes.

1. Merge settings: squash only, delete merged branches, PR title as the commit title.
   Works on every plan:
   ```bash
   ! gh api -X PATCH repos/thuansec/iac-compliance-enforcer \
       -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
       -F delete_branch_on_merge=true -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY
   ```
2. Server-side gate, available since the repository went public (on a private Free repository the
   API answers *"Upgrade to GitHub Pro or make this repository public"*). The second ruleset makes
   `v*` and `policies-v*` tags immutable: once pushed, nobody can move or delete them (edit the
   ruleset to fix a mistaken tag). The last command is needed only for step 3:
   ```bash
   ! gh api -X POST repos/thuansec/iac-compliance-enforcer/rulesets --input docs/ci/main-ruleset.json
   ! gh api -X POST repos/thuansec/iac-compliance-enforcer/rulesets --input docs/ci/tags-ruleset.json
   ! gh api -X PATCH repos/thuansec/iac-compliance-enforcer -F allow_auto_merge=true
   ```
   Check the field names against the current REST "Create a repository ruleset" docs first.
   `integration_id` 15368 is GitHub Actions, so only Actions can satisfy `ci-ok`.
   Required reviews stay at 0: the loop opens PRs under your account, and GitHub doesn't let you
   approve your own PR. To approve every PR yourself, give the loop its own GitHub identity (a bot
   account or GitHub App) and raise `required_approving_review_count` to 1.
3. With the ruleset active you may set `"auto_merge": true` in `.claude/loop-policy.json`. The loop
   can then hand merging to GitHub (`gh pr merge --auto --squash`), and GitHub enforces the checks.

## Rules of thumb
- One task, one branch, one PR, and only one loop PR open at a time, so `main` never needs rebasing.
- Branch names: `<type>/T-xxxx-<slug>`, where type is the Conventional Commit type
  (`feat`, `fix`, `docs`, `test`, `chore`, `ci`, `refactor`).
- Update a stale branch by **merging** `origin/main` into it. Never rebase a pushed branch: that
  needs a force push, which is blocked. The squash merge keeps `main` linear anyway.
- Humans can still push directly with `! git ...` (hooks don't apply to you). Only the ruleset stops that.
