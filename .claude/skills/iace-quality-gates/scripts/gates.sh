#!/usr/bin/env bash
# Quality gates for iac-compliance-enforcer (iace).
#
#   gates.sh quick   fast feedback while developing (format, vet, short tests, policy tests)
#   gates.sh full    definition of done before every commit (all Makefile contract targets
#                    plus loop discipline checks on the working-tree diff)
#
# Commands come from the Makefile contract (see the iace-quality-gates skill) so CI, humans and
# the loop run the same checks. Before the Makefile exists (bootstrap), Go checks fall back
# to plain go commands. Missing tools FAIL (fail closed); only checks whose inputs don't exist
# yet are SKIPped. Output stays compact: failing checks show the last lines of their log.
# A passing full run records the tree fingerprint in .cache/gates/full.pass; the guard hook only
# allows `git commit` when that stamp matches the tree being committed.
set -uo pipefail

mode="${1:-}"
[[ "$mode" == quick || "$mode" == full ]] || { echo "usage: gates.sh quick|full" >&2; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT" || exit 2
LOGDIR="$(mktemp -d)"
trap 'rm -rf "$LOGDIR"' EXIT

CONTRACT=(fmt-check lint test cover-check policy-check policy-test vuln build tidy-check)
pass=0 fail=0 skip=0 warn=0
failed=()

result() { # status name detail
	printf '%-5s %-15s %s\n' "$1" "$2" "${3:-}"
	case "$1" in
	PASS) pass=$((pass + 1)) ;;
	FAIL) fail=$((fail + 1)); failed+=("$2") ;;
	SKIP) skip=$((skip + 1)) ;;
	WARN) warn=$((warn + 1)) ;;
	esac
}

run() { # name command...
	local name="$1" start=$SECONDS log="$LOGDIR/$1.log"
	shift
	local cmd="$*"
	cmd="${cmd%%$'\n'*}"
	if "$@" >"$log" 2>&1; then
		result PASS "$name" "($((SECONDS - start))s)"
	else
		result FAIL "$name" "($((SECONDS - start))s) ${cmd:0:72}"
		tail -n 25 "$log" | sed 's/^/      | /'
	fi
}

has_target() { [[ -f Makefile ]] && grep -qE "^$1:" Makefile; }

echo "iace gates · mode=$mode · root=$ROOT"
FINGERPRINT="$(dirname "${BASH_SOURCE[0]}")/tree-fingerprint.sh"
fp_start=""
if [[ "$mode" == full ]] && git rev-parse --git-dir >/dev/null 2>&1; then
	fp_start=$(bash "$FINGERPRINT" "$ROOT" 2>/dev/null || true)
fi

# --- Harness: hook test suite (fast; guards the guards) ---------------------------------------
if [[ -x .claude/hooks/tests/run.sh ]]; then
	run hook-tests .claude/hooks/tests/run.sh
fi

# --- Go and policies -------------------------------------------------------------------------
if [[ ! -f go.mod ]]; then
	result SKIP go "no go.mod yet (bootstrap)"
elif [[ -f Makefile ]]; then
	missing=()
	for t in "${CONTRACT[@]}"; do has_target "$t" || missing+=("$t"); done
	((${#missing[@]})) && result FAIL makefile "missing contract targets: ${missing[*]}"
	if [[ "$mode" == quick ]]; then
		has_target fmt-check && run fmt-check make --no-print-directory fmt-check
		run vet go vet ./...
		run test-short go test -short -count=1 ./...
		if [[ -d policies ]] && has_target policy-test; then run policy-test make --no-print-directory policy-test; fi
	else
		for t in "${CONTRACT[@]}"; do
			has_target "$t" && run "$t" make --no-print-directory "$t"
		done
		run mod-verify go mod verify
	fi
else
	result WARN makefile "absent: using bootstrap fallback until T-0004 adds the contract targets"
	# pipefail + explicit status: a missing or crashing gofmt must FAIL, not look like "no diffs".
	run gofmt bash -c 'set -o pipefail; command -v gofmt >/dev/null || { echo "gofmt not found"; exit 127; }
		out=$(find . -name "*.go" -not -path "./.git/*" -print0 | xargs -0 -r gofmt -l) || exit 1
		[[ -z "$out" ]] || { echo "unformatted files:"; echo "$out"; exit 1; }'
	run vet go vet ./...
	run test go test -count=1 ./...
	run build go build ./...
fi

# --- Workflows (when the Makefile lint target does not already cover actionlint) --------------
if compgen -G ".github/workflows/*.y*ml" >/dev/null && ! grep -q actionlint Makefile 2>/dev/null; then
	if [[ -f tools/actionlint/go.mod ]]; then
		run actionlint go tool -modfile=tools/actionlint/go.mod actionlint
	elif command -v actionlint >/dev/null; then
		run actionlint actionlint
	else
		result FAIL actionlint "workflows exist but actionlint is unavailable (pin it in tools/actionlint/go.mod)"
	fi
fi

# --- Loop discipline on the working-tree diff (full mode) ------------------------------------
if [[ "$mode" == full ]] && git rev-parse --verify -q HEAD >/dev/null 2>&1; then
	added="$LOGDIR/added.txt"
	if [[ -n "${IACE_GATES_BASE:-}" ]]; then
		# CI: every line the pull request adds relative to its base (e.g. origin/main).
		git diff "$IACE_GATES_BASE"...HEAD --unified=0 --no-color | grep -E '^\+[^+]' | cut -c2- >"$added"
	else
		# Local: added lines from tracked changes, plus new untracked text files (<1 MiB).
		git diff HEAD --unified=0 --no-color | grep -E '^\+[^+]' | cut -c2- >"$added"
		while IFS= read -r -d '' f; do
			[[ -f "$f" && $(wc -c <"$f") -lt 1048576 ]] && grep -Iq . "$f" && cat "$f" >>"$added"
		done < <(git ls-files --others --exclude-standard -z)
	fi

	# Same credential formats as .claude/hooks/block-secrets.sh, applied to file content.
	secret_re='((AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}'
	secret_re+='|(^|[^A-Za-z0-9])sk-(ant-[A-Za-z0-9_-]{20,}|(proj-)?[A-Za-z0-9_-]{40,})'
	secret_re+='|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}'
	secret_re+='|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AccountKey=[A-Za-z0-9+/]{40,}'
	secret_re+='|[A-Za-z][A-Za-z0-9+.-]*://[^/:@[:space:]]+:[^/@[:space:]$]{3,}@)'
	hits=$(grep -nE "$secret_re" "$added" | grep -v 'iace:fake-secret' | head -5)
	if [[ -n "$hits" ]]; then
		result FAIL secrets "secret-like strings in the diff (mark deliberate fixture values with a trailing '# iace:fake-secret' comment)"
		# Never echo the match itself: a real secret would end up in logs and transcripts.
		sed -E "s#$secret_re#<redacted>#g; s/^(.{0,80}).*/      | \1/" <<<"$hits"
	else
		result PASS secrets
	fi

	skips=$(grep -nE '\bt\.Skip(f|Now)?\(' "$added" | grep -vE 'T-[0-9]{4}' | head -5)
	if [[ -n "$skips" ]]; then
		result FAIL test-skips "new t.Skip without a task reference (T-xxxx)"
		sed 's/^/      | /' <<<"$skips"
	else
		result PASS test-skips
	fi

	todos=$(grep -nE '\b(TODO|FIXME|XXX)\b' "$added" | grep -vE 'T-[0-9]{4}' | head -5)
	[[ -n "$todos" ]] && result WARN todos "TODO/FIXME without a task ID; add one or a backlog task"

	# List untracked files individually; otherwise a new directory hides a new PROGRESS.md.
	changed=$(git status --porcelain --untracked-files=all | awk '{print $NF}')
	if grep -qvE '^(docs/|\.claude/|CLAUDE\.md|README\.md)' <<<"$changed" && ! grep -q '^docs/plan/PROGRESS.md$' <<<"$changed"; then
		result WARN progress "code changed but docs/plan/PROGRESS.md not updated yet"
	fi
fi

echo "summary: $pass pass, $fail fail, $skip skip, $warn warn"
if ((fail > 0)); then
	echo "GATES FAILED: ${failed[*]}"
	exit 1
fi
if [[ "$mode" == full && -n "$fp_start" ]]; then
	fp_end=$(bash "$FINGERPRINT" "$ROOT" 2>/dev/null || true)
	if [[ "$fp_end" == "$fp_start" ]]; then
		mkdir -p .cache/gates && printf '%s\n' "$fp_end" >.cache/gates/full.pass.tmp &&
			mv .cache/gates/full.pass.tmp .cache/gates/full.pass
		echo "stamp: .cache/gates/full.pass records this tree; git commit is allowed for it"
	else
		echo "no stamp: files changed while the gates ran; run gates.sh full again before committing"
	fi
fi
echo "GATES PASSED"
