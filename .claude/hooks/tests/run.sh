#!/usr/bin/env bash
# Test suite for the project hooks: block-secrets.sh, guard-loop.py and format-file.sh.
# Run after any change to .claude/hooks, .claude/settings.json or .claude/loop-policy.json;
# gates.sh runs it too.
#
#   .claude/hooks/tests/run.sh [-v]
#
# Cases live in cases.jsonl (fake secrets carry "marker": "iace:fake-secret" so the gates'
# secret scan skips them). Guard cases run against a throwaway project with a known policy, so
# results never depend on this repository's state. Scenario tests below cover the branch rules,
# the commit and push gates, the merge gate (with a fake `gh`) and the formatter.
set -uo pipefail

HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$(cd "$HOOKS/../.." && pwd)"
VERBOSE="${1:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0 fail=0
GIT=(git -c user.email=t@t -c user.name=t)

ok() { pass=$((pass + 1)); [[ "$VERBOSE" == "-v" ]] && printf '  ok    %s\n' "$1"; return 0; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; }

run_hook() { # hook project-dir < json ; prints exit code, leaves output in $WORK/stdout|stderr
	local hook="$1" proj="$2"
	case "$hook" in
	guard) CLAUDE_PROJECT_DIR="$proj" python3 "$HOOKS/guard-loop.py" >"$WORK/stdout" 2>"$WORK/stderr" ;;
	secrets) CLAUDE_PROJECT_DIR="$proj" bash "$HOOKS/block-secrets.sh" >"$WORK/stdout" 2>"$WORK/stderr" ;;
	format) CLAUDE_PROJECT_DIR="$proj" bash "$HOOKS/format-file.sh" >"$WORK/stdout" 2>"$WORK/stderr" ;;
	esac
	echo $?
}

expect() { # name expected(allow|ask|block) rc
	local got
	if [[ "$3" -eq 2 ]]; then got=block
	elif grep -q '"permissionDecision": "ask"' "$WORK/stdout" 2>/dev/null; then got=ask
	elif [[ "$3" -eq 0 ]]; then got=allow
	else got="error(exit $3)"; fi
	if [[ "$got" == "$2" ]]; then ok "$1"; else bad "$1 (expected $2, got $got: $(head -c 240 "$WORK/stderr"))"; fi
}

guard_cmd() { # project command [cwd] ; prints exit code
	jq -nc --arg c "$2" --arg cwd "${3:-$1}" '{tool_name: "Bash", tool_input: {command: $c}, cwd: $cwd}' | run_hook guard "$1"
}

make_project() { # dir policy-json : a minimal project with the fingerprint script and a policy
	mkdir -p "$1/.claude/skills/iace-quality-gates/scripts" "$1/.claude/hooks" "$1/.claude/agents" "$1/docs/plan" "$1/src"
	cp "$PROJECT/.claude/skills/iace-quality-gates/scripts/tree-fingerprint.sh" "$1/.claude/skills/iace-quality-gates/scripts/"
	printf '%s\n' "$2" >"$1/.claude/loop-policy.json"
	printf '/.cache/\n' >"$1/.gitignore"
	echo 'package src' >"$1/src/a.go"
	echo '# backlog' >"$1/docs/plan/BACKLOG.md"
	echo '# progress' >"$1/docs/plan/PROGRESS.md"
	echo '# claude' >"$1/CLAUDE.md"
	git -C "$1" init -q -b main
	git -C "$1" remote add origin https://github.com/acme/demo.git
	git -C "$1" add -A && "${GIT[@]}" -C "$1" commit -qm init
}

stamp() { # dir : record a passing full-gates run for the current content
	mkdir -p "$1/.cache/gates" && bash "$1/.claude/skills/iace-quality-gates/scripts/tree-fingerprint.sh" "$1" >"$1/.cache/gates/full.pass"
}

POLICY_ALL='{"git_workflow":"pull-request","default_branch":"main","push_feature_branches":true,"open_pull_requests":true,"merge_pull_requests":true,"merge_method":"squash","auto_merge":false,"required_check":"ci-ok","live_api_calls":false}'

# --- 1. table cases --------------------------------------------------------------------------
P="$WORK/proj"
make_project "$P" "$POLICY_ALL"
git -C "$P" switch -q -c feat/T-0001-test
while IFS= read -r line; do
	[[ -z "$line" ]] && continue
	hook=$(jq -r .hook <<<"$line")
	input=$(jq -c --arg cwd "$P" '{tool_name: (.tool_name // "Bash"), tool_input: .tool_input, cwd: (.cwd // $cwd)}' <<<"$line")
	rc=$(printf '%s' "$input" | run_hook "$hook" "$P")
	expect "$hook: $(jq -r .name <<<"$line")" "$(jq -r .expect <<<"$line")" "$rc"
done <"$HOOKS/tests/cases.jsonl"

# --- 2. fail closed on invalid input ----------------------------------------------------------
for hook in guard secrets; do
	expect "$hook: invalid JSON input" block "$(printf 'not json' | run_hook "$hook" "$P")"
done

# --- 3. the policy decides push, PR and merge permissions --------------------------------------
NP="$WORK/nopush"
make_project "$NP" '{"push_feature_branches":false,"open_pull_requests":false,"merge_pull_requests":false}'
git -C "$NP" switch -q -c feat/T-0002-x && stamp "$NP"
expect "policy: push not allowed" block "$(guard_cmd "$NP" 'git push -u origin HEAD')"
expect "policy: PR creation not allowed" block "$(guard_cmd "$NP" 'gh pr create --fill')"
expect "policy: merging not allowed" block "$(guard_cmd "$NP" 'gh pr merge 1 --squash --match-head-commit abc')"
MP="$WORK/nopolicy"
make_project "$MP" '{}' && rm "$MP/.claude/loop-policy.json"
git -C "$MP" switch -q -c feat/T-0003-x && stamp "$MP"
expect "policy: missing file grants no push" block "$(guard_cmd "$MP" 'git push -u origin HEAD')"

# --- 4. branch rule and commit gate ------------------------------------------------------------
R="$WORK/repo"
make_project "$R" "$POLICY_ALL"
commit() { guard_cmd "$R" 'git commit -m "feat: x (T-0101)"' "${1:-$R}"; }
expect "branch rule: commit on main is blocked" block "$(commit)"
git -C "$R" switch -q -c feat/T-0101-x
expect "commit gate: clean tree on a feature branch" allow "$(commit)"
echo '// change' >>"$R/src/a.go"
expect "commit gate: code change without stamp" block "$(commit)"
stamp "$R"
expect "commit gate: code change with matching stamp" allow "$(commit)"
echo '- result: done' >>"$R/docs/plan/BACKLOG.md" && echo '### entry' >>"$R/docs/plan/PROGRESS.md"
expect "commit gate: plan updates after the gates keep the stamp valid" allow "$(commit)"
echo '// edited after gates' >>"$R/src/a.go"
expect "commit gate: code edited after the gates" block "$(commit)"
expect "commit gate: follows cd into the project" block "$(guard_cmd "$R" "cd $R/src && git commit -m x" /tmp)"
expect "commit gate: follows git -C into the project" block "$(guard_cmd "$R" "git -C $R commit -m x" /tmp)"
expect "commit gate: follows a cd through a variable" block "$(guard_cmd "$R" "D=$R; cd \"\$D\" && git commit -m x" /tmp)"
git -C "$R" stash push -q -u -m tmp
echo '- groomed' >>"$R/docs/plan/BACKLOG.md"
expect "commit gate: plan-only commit needs no stamp" allow "$(commit)"
O="$WORK/other"
mkdir -p "$O" && git -C "$O" init -q -b main && echo x >"$O/f" && git -C "$O" add f
expect "commit gate: other repositories are not gated" allow "$(commit "$O")"

# --- 5. push gate --------------------------------------------------------------------------------
Q="$WORK/push"
make_project "$Q" "$POLICY_ALL"
git -C "$Q" switch -q -c feat/T-0102-y
echo 'change' >>"$Q/src/a.go"
expect "push gate: uncommitted changes" block "$(guard_cmd "$Q" 'git push -u origin HEAD')"
git -C "$Q" add -A && "${GIT[@]}" -C "$Q" commit -qm change
expect "push gate: committed but the gates never ran" block "$(guard_cmd "$Q" 'git push -u origin HEAD')"
stamp "$Q"
expect "push gate: gates passed on this content" allow "$(guard_cmd "$Q" 'git push -u origin HEAD')"
expect "push gate: plain push of the current branch" allow "$(guard_cmd "$Q" 'git push')"
expect "push gate: explicit current branch" allow "$(guard_cmd "$Q" 'git push origin feat/T-0102-y')"
expect "push gate: never to main" block "$(guard_cmd "$Q" 'git push origin main')"
expect "push gate: never another branch" block "$(guard_cmd "$Q" 'git push origin feat/T-0999-z')"
git -C "$Q" switch -q main && echo m >"$Q/src/m.go" && git -C "$Q" add -A && "${GIT[@]}" -C "$Q" commit -qm m
git -C "$Q" switch -q feat/T-0102-y && "${GIT[@]}" -C "$Q" merge -q --no-edit main
expect "push gate: after merging main the gates must run again" block "$(guard_cmd "$Q" 'git push')"
stamp "$Q"
expect "push gate: merged content checked by the gates" allow "$(guard_cmd "$Q" 'git push')"
git -C "$Q" switch -q main
expect "push gate: pushing while on main" block "$(guard_cmd "$Q" 'git push')"

# --- 6. merge gate (fake gh returns canned PR state) -------------------------------------------
FG="$WORK/fakegh"
mkdir -p "$FG"
cat >"$FG/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == pr && "$2" == view ]]; then [[ -n "${FAKE_PR_FAIL:-}" ]] && exit 1; cat "$FAKE_PR"; exit 0; fi
if [[ "$1" == api && "$2" == repos/*/compare/* ]]; then echo "${FAKE_BEHIND:-0}"; exit 0; fi
echo "fake gh: unexpected $*" >&2; exit 1
EOF
chmod +x "$FG/gh"
GREEN='{"number":7,"state":"OPEN","isDraft":false,"baseRefName":"main","headRefName":"feat/T-0002-x","headRefOid":"abc123","mergeable":"MERGEABLE","mergeStateStatus":"CLEAN","statusCheckRollup":[{"__typename":"CheckRun","name":"gates","status":"COMPLETED","conclusion":"SUCCESS"},{"__typename":"CheckRun","name":"ci-ok","status":"COMPLETED","conclusion":"SUCCESS"}]}'
merge_case() { # name expected pr-json [behind] [command] [fail]
	printf '%s' "$3" >"$WORK/pr.json"
	local cmd="${5:-gh pr merge 7 --squash --delete-branch --match-head-commit abc123}" rc
	rc=$(export PATH="$FG:$PATH" FAKE_PR="$WORK/pr.json" FAKE_BEHIND="${4:-0}" FAKE_PR_FAIL="${6:-}"; guard_cmd "$P" "$cmd")
	expect "merge gate: $1" "$2" "$rc"
}
merge_case "green, up to date, pinned head" allow "$GREEN"
merge_case "required check still running" block "$(jq -c '.statusCheckRollup[1].status="IN_PROGRESS" | .statusCheckRollup[1].conclusion=null' <<<"$GREEN")"
merge_case "a check failed" block "$(jq -c '.statusCheckRollup[0].conclusion="FAILURE"' <<<"$GREEN")"
merge_case "required check missing" block "$(jq -c '.statusCheckRollup=[.statusCheckRollup[0]]' <<<"$GREEN")"
merge_case "external status failing" block "$(jq -c '.statusCheckRollup += [{"__typename":"StatusContext","context":"ext","state":"FAILURE"}]' <<<"$GREEN")"
merge_case "merge conflicts" block "$(jq -c '.mergeable="CONFLICTING" | .mergeStateStatus="DIRTY"' <<<"$GREEN")"
merge_case "mergeability not computed yet" block "$(jq -c '.mergeable="UNKNOWN" | .mergeStateStatus="UNKNOWN"' <<<"$GREEN")"
merge_case "behind main" block "$GREEN" 2
merge_case "draft" block "$(jq -c '.isDraft=true' <<<"$GREEN")"
merge_case "already merged" block "$(jq -c '.state="MERGED"' <<<"$GREEN")"
merge_case "wrong base branch" block "$(jq -c '.baseRefName="develop"' <<<"$GREEN")"
merge_case "head moved after verification" block "$GREEN" 0 'gh pr merge 7 --squash --match-head-commit def456'
merge_case "gh cannot read the PR" block "$GREEN" 0 '' 1
merge_case "other repository" block "$GREEN" 0 'gh pr merge 7 --squash --match-head-commit abc123 -R evil/repo'

# --- 7. formatter: formats project files, leaves everything else alone -------------------------
F="$WORK/fmt"
mkdir -p "$F/policies" "$F/src" "$F/infra"
printf 'package x\nallow if {\n  input.a==1\n}\n' >"$F/policies/x.rego"
printf 'package src\nfunc  f( )  { }\n' >"$F/src/a.go"
printf 'resource "x" "y" {\na = 1\n  bbb = 2\n}\n' >"$F/infra/main.tf"
printf 'package src\nfunc  g( )  { }\n' >"$WORK/outside.go"
for f in policies/x.rego src/a.go infra/main.tf; do
	before=$(sha256sum "$F/$f")
	jq -nc --arg p "$F/$f" '{tool_input: {file_path: $p}}' | run_hook format "$F" >/dev/null
	case "${f##*.}" in go) tool=gofmt ;; rego) tool=opa ;; *) tool=terraform ;; esac
	if ! command -v "$tool" >/dev/null 2>&1; then ok "format: $f ($tool not installed, skipped)"
	elif [[ "$(sha256sum "$F/$f")" != "$before" ]]; then ok "format: $f reformatted"
	else bad "format: $f not reformatted"; fi
done
before=$(sha256sum "$WORK/outside.go")
jq -nc --arg p "$WORK/outside.go" '{tool_input: {file_path: $p}}' | run_hook format "$F" >/dev/null
[[ "$(sha256sum "$WORK/outside.go")" == "$before" ]] && ok "format: file outside the project untouched" || bad "format: touched a file outside the project"
printf 'package x\nallow if {\n' >"$F/policies/broken.rego"
rc=$(jq -nc --arg p "$F/policies/broken.rego" '{tool_input: {file_path: $p}}' | run_hook format "$F")
[[ "$rc" -eq 0 ]] && ok "format: unparseable file exits 0" || bad "format: unparseable file exit $rc"

echo "hook tests: $pass passed, $fail failed"
((fail == 0))
