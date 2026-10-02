# Going public (T-1107, D-08)

The owner made the repository public on 2026-10-02 (decision D-08). This happened earlier than
T-1107 had planned, which was after the security sign-off (T-1105). This page records the checks
run after the switch and the GitHub settings the owner turns on.

## History check (2026-10-02)
Scope: all 17 commits on `main` and on the 6 pull-request refs (`refs/pull/*/head`; GitHub keeps
them after branches are deleted), read from a mirror clone.

| check | result |
|---|---|
| the gates' credential patterns (`gates.sh`), on every added line and every commit message | 12 lines, all test fixtures in `.claude/hooks/tests/cases.jsonl` marked `iace:fake-secret`: runs of one repeated character, AWS's documented example access key ID, and a common placeholder password |
| gitleaks v8.30.1 (`gitleaks git --log-opts=--all`) | no leaks |
| author emails | 10 commits carry the owner's personal email address and 7 the GitHub noreply address (squash merges). The personal address stays visible in that history and in the pull-request refs. |

To stop adding the personal address, commit with the GitHub noreply address
(`git config user.email <id>+<user>@users.noreply.github.com`). Removing it from existing commits
would take GitHub Support (for pull-request refs) or a fresh repository. That is the owner's call.

## Settings
The owner applies these: the loop's token cannot change repository settings, and the guard blocks
GitHub writes. Run each command with `!` in Claude Code or in a terminal, with a token that has
**Administration: write**. Check field names against the current REST docs first.

| setting | why | command | status on 2026-10-02 |
|---|---|---|---|
| `main` ruleset | server-side merge gate for everyone: pull request, `ci-ok` green, branch up to date, squash only, no force push or deletion | `gh api -X POST repos/thuansec/iac-compliance-enforcer/rulesets --input docs/ci/main-ruleset.json` | not applied |
| release-tag ruleset | `v*` and `policies-v*` tags cannot be moved or deleted once pushed | `gh api -X POST repos/thuansec/iac-compliance-enforcer/rulesets --input docs/ci/tags-ruleset.json` | not applied |
| secret scanning with push protection | alerts on, and blocks pushes of, known credential formats | `gh api -X PATCH repos/thuansec/iac-compliance-enforcer -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'` | unknown (the loop's token cannot read it) |
| private vulnerability reporting | researchers can report privately (SECURITY.md, T-0007) | `gh api -X PUT repos/thuansec/iac-compliance-enforcer/private-vulnerability-reporting` | off |
| Dependabot alerts | alerts on vulnerable Go modules and actions | `gh api -X PUT repos/thuansec/iac-compliance-enforcer/vulnerability-alerts` | unknown (the loop's token cannot read it) |
| approval for outside contributors' workflow runs | pull requests from forks run CI only after approval | `gh api -X PUT repos/thuansec/iac-compliance-enforcer/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors` | unknown (the loop's token cannot read it) |

Once the `main` ruleset is active, `"auto_merge": true` in `.claude/loop-policy.json` becomes
possible (see `docs/ci/branch-workflow.md`). That is optional and the owner's decision.

## Verification
The loop can read the rulesets (`gh api repos/thuansec/iac-compliance-enforcer/rulesets`) and
private vulnerability reporting. The other settings need a token with Administration: read.
