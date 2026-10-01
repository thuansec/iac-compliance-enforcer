#!/usr/bin/env bash
# Print a fingerprint of the working tree relative to HEAD (tracked changes, staged or not, plus
# untracked non-ignored files). It changes the moment any file changes or HEAD moves.
#
# gates.sh full stores it in .cache/gates/full.pass when every check passes, and the guard hook
# (.claude/hooks/guard-loop.py) compares it before allowing `git commit`. A commit is therefore
# only possible for the exact tree the full gates checked.
#
# docs/plan/BACKLOG.md and docs/plan/PROGRESS.md are excluded: the loop records the task result
# there after the gates run, and those edits must not invalidate the stamp.
#
#   tree-fingerprint.sh [repo-root]
set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"
exclude=(':(exclude)docs/plan/BACKLOG.md' ':(exclude)docs/plan/PROGRESS.md')

{
	if head=$(git rev-parse --verify -q HEAD); then
		echo "$head"
		git -c core.quotepath=false diff HEAD --binary --no-color --no-ext-diff -- . "${exclude[@]}"
	else
		echo "no-head"
		git -c core.quotepath=false ls-files --cached -z -- . "${exclude[@]}" | sort -z | xargs -0 -r sha256sum --
	fi
	git -c core.quotepath=false ls-files --others --exclude-standard -z -- . "${exclude[@]}" |
		sort -z | xargs -0 -r sha256sum --
} | sha256sum | cut -d' ' -f1
