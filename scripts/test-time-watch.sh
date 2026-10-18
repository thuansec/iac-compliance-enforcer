#!/usr/bin/env bash
# test-time-watch.sh OUTPUT LIMIT_SECONDS
#
# Reads the output of `go test ./...` (non-verbose: one "ok|FAIL <package> <seconds>s" line per
# package) and warns about every package that took longer than LIMIT_SECONDS. go test stops a
# package at 10 minutes, so make test watches a lower line (T-0125): a package creeping towards the
# timeout is reported long before CI fails on it. Under GitHub Actions the warning is also an
# annotation. It only warns: the timeout itself stays the gate.
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: test-time-watch.sh OUTPUT LIMIT_SECONDS" >&2
	exit 2
fi
output=$1
limit=$2

awk -v limit="$limit" -v gha="${GITHUB_ACTIONS:-}" '
	$1 == "ok" || $1 == "FAIL" {
		secs = $3
		if (secs !~ /^[0-9.]+s$/) next
		sub(/s$/, "", secs)
		timed++
		if (secs + 0 > limit + 0) {
			msg = sprintf("test-time-watch: %s took %ss, over the %ss watch line (go test stops a package at 600s)", $2, secs, limit)
			print msg > "/dev/stderr"
			if (gha == "true") printf "::warning title=Slow test package::%s\n", msg
			slow++
		}
	}
	END {
		# No timing line means the watch read nothing (an empty file, or go test flags changed):
		# say so rather than report every package as fast.
		if (!timed) print "test-time-watch: no package timings found; the watch did not run" > "/dev/stderr"
		else if (!slow) printf "test-time-watch: every package under %ss\n", limit
	}
' "$output"
