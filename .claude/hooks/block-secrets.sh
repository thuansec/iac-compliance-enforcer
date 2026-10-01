#!/usr/bin/env bash
# PreToolUse hook (matcher: Bash): block shell commands that contain credentials.
#
# Exit 2 blocks the command and shows the reason to Claude; exit 0 allows it.
# Fails closed: if jq is missing or the hook input cannot be parsed, the command is blocked,
# because an unchecked command is exactly what this hook exists to prevent.
#
# Patterns match concrete credential formats rather than bare prefixes, so ordinary text such as
# "task-selection" or "TestDisk-encryption" passes, and variable references such as
# $DB_PASSWORD pass. A match is never echoed back, so a real secret is not repeated into logs.
# Files are covered separately: the quality gates scan diffs for the same formats before commit.
set -uo pipefail

block() {
	echo "BLOCKED by .claude/hooks/block-secrets.sh: $1" >&2
	echo "Keep credentials out of commands: reference environment variables, or create fixture files with the Write tool using obviously fake values." >&2
	exit 2
}

command -v jq >/dev/null 2>&1 || block "jq is not installed, so the command cannot be checked"

input=$(cat) || block "could not read the hook input"
cmd=$(printf '%s' "$input" | jq -er '(.tool_input // {}) | if type == "object" then (.command // "") else "" end' 2>/dev/null) ||
	block "the hook input is not valid JSON"
[[ -n "$cmd" ]] || exit 0

# Case-sensitive credential formats:
#   AWS access key IDs (long-term AKIA, temporary ASIA); GitHub classic and fine-grained tokens;
#   Anthropic and OpenAI-style keys (the "sk-" must start a word and be followed by a long key,
#   so words like "task-" never match); Slack tokens; Google API keys; PEM private keys;
#   Azure storage account keys; and user:password embedded in a URL (not a $VARIABLE).
token_re='(AKIA|ASIA)[0-9A-Z]{16}'
token_re+='|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}'
token_re+='|(^|[^A-Za-z0-9])sk-(ant-[A-Za-z0-9_-]{20,}|(proj-)?[A-Za-z0-9_-]{40,})'
token_re+='|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}'
token_re+='|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AccountKey=[A-Za-z0-9+/]{40,}'
token_re+='|[A-Za-z][A-Za-z0-9+.-]*://[^/:@[:space:]]+:[^/@[:space:]$]{3,}@'

# Case-insensitive: a literal password value after "password=" or "passwd=", e.g.
# --password=hunter2 or PGPASSWORD="s3cret". Empty values and $VARIABLE references pass.
password_re="pass(word|wd)=[\"']?[^\$\"'[:space:]<{]"

if printf '%s\n' "$cmd" | grep -qE -- "$token_re"; then
	block "the command contains what looks like an API key, token, private key or URL credentials"
fi
if printf '%s\n' "$cmd" | grep -qiE -- "$password_re"; then
	block "the command sets a literal password (reference an environment variable instead)"
fi
exit 0
