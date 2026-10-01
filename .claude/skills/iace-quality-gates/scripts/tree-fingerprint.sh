#!/usr/bin/env bash
# Print a content fingerprint of the working tree: the git tree hash of every tracked and
# untracked (non-ignored) file as it is on disk right now. It depends on file content only, not
# on HEAD, so committing does not change it, while any edit, merge or new file does.
#
# gates.sh full stores it in .cache/gates/full.pass when every check passes. The guard hook
# (.claude/hooks/guard-loop.py) compares it before `git commit` and `git push`, so a commit or
# push is only possible for exactly the content the full gates checked.
#
# docs/plan/BACKLOG.md and docs/plan/PROGRESS.md are excluded: the loop records the task result
# there after the gates run, and those edits must not invalidate the stamp.
#
#   tree-fingerprint.sh [repo-root]
set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"
gitdir=$(git rev-parse --absolute-git-dir)
tmp_index=$(mktemp)
trap 'rm -f "$tmp_index" "$tmp_index.lock"' EXIT

# A copy of the real index lets git reuse its stat cache; without one, start empty.
if [[ -f "$gitdir/index" ]]; then cp "$gitdir/index" "$tmp_index"; else rm -f "$tmp_index"; fi
export GIT_INDEX_FILE="$tmp_index"
git add -A -- . >/dev/null
git rm --cached -q --ignore-unmatch -- docs/plan/BACKLOG.md docs/plan/PROGRESS.md >/dev/null
git write-tree
