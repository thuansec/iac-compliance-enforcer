#!/usr/bin/env bash
# Test suite for the project hooks: block-secrets.sh, guard-loop.py and format-file.sh.
# Run after any change to .claude/hooks or .claude/settings.json; gates.sh runs it too.
#
#   .claude/hooks/tests/run.sh [-v]
#
# Cases live in cases.jsonl (fake secrets carry "marker": "iace:fake-secret" so the gates'
# secret scan skips them). Scenario tests below build throwaway git repos for the commit gate.
set -uo pipefail

HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$(cd "$HOOKS/../.." && pwd)"
VERBOSE="${1:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0 fail=0

ok() { pass=$((pass + 1)); [[ "$VERBOSE" == "-v" ]] && printf '  ok    %s\n' "$1"; return 0; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; }

run_hook() { # hook-name project-dir < json ; prints exit code
	local hook="$1" proj="$2"
	case "$hook" in
	guard) CLAUDE_PROJECT_DIR="$proj" python3 "$HOOKS/guard-loop.py" >/dev/null 2>"$WORK/stderr" ;;
	secrets) CLAUDE_PROJECT_DIR="$proj" bash "$HOOKS/block-secrets.sh" >/dev/null 2>"$WORK/stderr" ;;
	format) CLAUDE_PROJECT_DIR="$proj" bash "$HOOKS/format-file.sh" >/dev/null 2>"$WORK/stderr" ;;
	esac
	echo $?
}

expect() { # name expected(allow|block) rc
	local got=allow
	[[ "$3" -eq 2 ]] && got=block
	if [[ "$got" == "$2" && "$3" -le 2 ]]; then ok "$1"; else bad "$1 (expected $2, exit $3: $(head -c 200 "$WORK/stderr"))"; fi
}

# --- 1. table cases --------------------------------------------------------------------------
while IFS= read -r line; do
	[[ -z "$line" ]] && continue
	hook=$(jq -r .hook <<<"$line")
	name=$(jq -r .name <<<"$line")
	want=$(jq -r .expect <<<"$line")
	input=$(jq -c --arg cwd "$PROJECT" '{tool_name: "Bash", tool_input: .tool_input, cwd: (.cwd // $cwd)}' <<<"$line")
	rc=$(printf '%s' "$input" | run_hook "$hook" "$PROJECT")
	expect "$hook: $name" "$want" "$rc"
done <"$HOOKS/tests/cases.jsonl"

# --- 2. fail closed on invalid input ----------------------------------------------------------
for hook in guard secrets; do
	rc=$(printf 'not json' | run_hook "$hook" "$PROJECT")
	expect "$hook: invalid JSON input" block "$rc"
done

# --- 3. push permission follows the BACKLOG loop settings --------------------------------------
P="$WORK/push-yes"
mkdir -p "$P/docs/plan"
printf '## Loop settings\n- push_to_remote: yes\n' >"$P/docs/plan/BACKLOG.md"
for c in 'git push origin main|allow' 'gh pr create --fill|allow' 'git push --force origin main|block'; do
	rc=$(jq -nc --arg c "${c%|*}" '{tool_input: {command: $c}, cwd: "/tmp"}' | run_hook guard "$P")
	expect "guard (push_to_remote: yes): ${c%|*}" "${c#*|}" "$rc"
done

# --- 4. commit gate: stamp must match the exact tree ------------------------------------------
R="$WORK/repo"
mkdir -p "$R/docs/plan" "$R/src" "$R/.claude/skills/iace-quality-gates/scripts"
cp "$PROJECT/.claude/skills/iace-quality-gates/scripts/tree-fingerprint.sh" "$R/.claude/skills/iace-quality-gates/scripts/"
printf '/.cache/\n' >"$R/.gitignore"
echo 'package src' >"$R/src/a.go"
printf '## Loop settings\n- push_to_remote: no\n' >"$R/docs/plan/BACKLOG.md"
echo '# progress' >"$R/docs/plan/PROGRESS.md"
git -C "$R" init -q -b main && git -C "$R" add -A && git -C "$R" -c user.email=t@t -c user.name=t commit -qm init

commit_rc() { jq -nc --arg cwd "$1" '{tool_input: {command: "git commit -m \"feat: x (T-0101)\""}, cwd: $cwd}' | run_hook guard "$R"; }
stamp() { mkdir -p "$R/.cache/gates" && bash "$R/.claude/skills/iace-quality-gates/scripts/tree-fingerprint.sh" "$R" >"$R/.cache/gates/full.pass"; }

expect "commit gate: clean tree needs no stamp" allow "$(commit_rc "$R")"
echo '// change' >>"$R/src/a.go"
expect "commit gate: code change without stamp" block "$(commit_rc "$R")"
stamp
expect "commit gate: code change with matching stamp" allow "$(commit_rc "$R")"
echo '- result: done' >>"$R/docs/plan/BACKLOG.md"
echo '### entry' >>"$R/docs/plan/PROGRESS.md"
expect "commit gate: plan updates after the gates keep the stamp valid" allow "$(commit_rc "$R")"
echo '// edited after gates' >>"$R/src/a.go"
expect "commit gate: code edited after the gates" block "$(commit_rc "$R")"
rc=$(jq -nc --arg c "cd $R/src && git commit -m x" '{tool_input: {command: $c}, cwd: "/tmp"}' | run_hook guard "$R")
expect "commit gate: follows cd into the project" block "$rc"
rc=$(jq -nc --arg c "git -C $R commit -m x" '{tool_input: {command: $c}, cwd: "/tmp"}' | run_hook guard "$R")
expect "commit gate: follows git -C into the project" block "$rc"
git -C "$R" stash push -q -u -m tmp
echo '- groomed' >>"$R/docs/plan/BACKLOG.md"
expect "commit gate: plan-only commit needs no stamp" allow "$(commit_rc "$R")"
O="$WORK/other"
mkdir -p "$O" && git -C "$O" init -q -b main && echo x >"$O/f" && git -C "$O" add f
expect "commit gate: commits in other repositories are not gated" allow "$(commit_rc "$O")"

# --- 5. formatter: formats project files, leaves everything else alone -------------------------
F="$WORK/fmt"
mkdir -p "$F/policies" "$F/src" "$F/infra"
printf 'package x\nallow if {\n  input.a==1\n}\n' >"$F/policies/x.rego"
printf 'package src\nfunc  f( )  { }\n' >"$F/src/a.go"
printf 'resource "x" "y" {\na = 1\n  bbb = 2\n}\n' >"$F/infra/main.tf"
printf 'package src\nfunc  g( )  { }\n' >"$WORK/outside.go"
for f in policies/x.rego src/a.go infra/main.tf; do
	before=$(sha256sum "$F/$f")
	jq -nc --arg p "$F/$f" '{tool_input: {file_path: $p}}' | run_hook format "$F" >/dev/null
	tool=${f##*.}
	if ! command -v "$([[ $tool == go ]] && echo gofmt || ([[ $tool == rego ]] && echo opa || echo terraform))" >/dev/null 2>&1; then
		ok "format: $f (formatter not installed, skipped)"
	elif [[ "$(sha256sum "$F/$f")" != "$before" ]]; then ok "format: $f reformatted"; else bad "format: $f not reformatted"; fi
done
before=$(sha256sum "$WORK/outside.go")
jq -nc --arg p "$WORK/outside.go" '{tool_input: {file_path: $p}}' | run_hook format "$F" >/dev/null
[[ "$(sha256sum "$WORK/outside.go")" == "$before" ]] && ok "format: file outside the project untouched" || bad "format: touched a file outside the project"
printf 'package x\nallow if {\n' >"$F/policies/broken.rego"
rc=$(jq -nc --arg p "$F/policies/broken.rego" '{tool_input: {file_path: $p}}' | run_hook format "$F")
[[ "$rc" -eq 0 ]] && ok "format: unparseable file exits 0" || bad "format: unparseable file exit $rc"

echo "hook tests: $pass passed, $fail failed"
((fail == 0))
