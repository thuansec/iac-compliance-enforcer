#!/usr/bin/env bash
# PostToolUse hook (matcher: Write|Edit): format the file Claude just wrote, so formatting never
# costs a gate failure or an iteration. Go via golangci-lint fmt when the repo has .golangci.yml
# (gofumpt + goimports, as the gates check), else gofmt; Rego via opa fmt; Terraform via
# terraform fmt. Only files inside the project are touched.
#
# Best effort by design: always exits 0. The quality gates remain the enforcement, and a file
# that does not parse is simply left as written.
set -uo pipefail

command -v jq >/dev/null 2>&1 || exit 0
file=$(jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
[[ -n "$file" && -f "$file" ]] || exit 0

root=$(realpath -m "${CLAUDE_PROJECT_DIR:-$PWD}")
path=$(realpath -m "$file")
[[ "$path" == "$root"/* ]] || exit 0

case "$path" in
*.go)
	if [[ -f "$root/.golangci.yml" ]] && command -v golangci-lint >/dev/null 2>&1; then
		(cd "$root" && golangci-lint fmt "$path") >/dev/null 2>&1 || gofmt -w "$path" >/dev/null 2>&1
	elif command -v gofmt >/dev/null 2>&1; then
		gofmt -w "$path" >/dev/null 2>&1
	fi
	;;
*.rego)
	command -v opa >/dev/null 2>&1 && opa fmt -w "$path" >/dev/null 2>&1
	;;
*.tf | *.tfvars)
	command -v terraform >/dev/null 2>&1 && terraform fmt "$path" >/dev/null 2>&1
	;;
esac
exit 0
