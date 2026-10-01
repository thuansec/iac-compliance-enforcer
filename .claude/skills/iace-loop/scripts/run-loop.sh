#!/usr/bin/env bash
# Fresh-context loop runner: one `claude -p "/iace-loop"` process per iteration, so every
# iteration starts with a clean context window and rebuilds its state from disk (BACKLOG,
# PROGRESS, git). Prefer this for long unattended runs; `/loop /iace-loop` is fine for short,
# supervised ones. Hooks, permissions, skills and CLAUDE.md are reloaded by every iteration.
#
#   run-loop.sh [--max-iterations N] [--budget-usd X] [--iteration-timeout 90m]
#               [--pause SECONDS] [--wait-pause SECONDS] [--permission-mode auto|acceptEdits|dontAsk]
#
# Stops when: an iteration reports LOOP_STATUS paused|done|blocked; the backlog has nothing
# ready; 3 consecutive iterations fail; the budget is spent; N iterations ran; or the file
# .cache/loop/STOP exists (touch it to stop after the current iteration).
# LOOP_STATUS waiting (a pull request's CI is still running) is not a failure: the runner
# sleeps --wait-pause seconds (default 300) and runs the next iteration, which picks the PR up.
# Logs: .cache/loop/logs/<timestamp>-iter<N>.jsonl (stream-json; `tail -f` it to watch).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
STATUS="$ROOT/.claude/skills/iace-loop/scripts/loop_status.py"
LOGDIR="$ROOT/.cache/loop/logs"
STOPFILE="$ROOT/.cache/loop/STOP"

max=50 budget="" iter_timeout="90m" pause=30 wait_pause=300 mode="${IACE_LOOP_PERMISSION_MODE:-auto}"
while (($#)); do
	case "$1" in
	--max-iterations) max="$2"; shift 2 ;;
	--budget-usd) budget="$2"; shift 2 ;;
	--iteration-timeout) iter_timeout="$2"; shift 2 ;;
	--pause) pause="$2"; shift 2 ;;
	--wait-pause) wait_pause="$2"; shift 2 ;;
	--permission-mode) mode="$2"; shift 2 ;;
	-h | --help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
	esac
done

for tool in claude jq python3 timeout; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
[[ "$max" =~ ^[0-9]+$ && "$pause" =~ ^[0-9]+$ && "$wait_pause" =~ ^[0-9]+$ ]] ||
	{ echo "--max-iterations, --pause and --wait-pause take integers" >&2; exit 2; }
[[ -z "$budget" || "$budget" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "--budget-usd takes a number" >&2; exit 2; }
mkdir -p "$LOGDIR"
cd "$ROOT" || exit 2

verdict() { python3 "$STATUS" --json | jq -r '.verdict // "unknown"'; }
last_progress() { python3 "$STATUS" --json | jq -r '.recent_progress[-1] // "-"'; }
add() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.4f", a + b }'; }
reached() { awk -v t="$1" -v b="$2" 'BEGIN { exit !(t >= b) }'; }

total=0 failures=0 ran=0 reason="max iterations reached ($max)"
echo "iace loop runner · root $ROOT · mode $mode · max $max · budget ${budget:-none} · timeout/iter $iter_timeout"
for ((i = 1; i <= max; i++)); do
	if [[ -f "$STOPFILE" ]]; then
		rm -f "$STOPFILE"
		reason="stop file found (.cache/loop/STOP)"
		break
	fi
	v=$(verdict)
	case "$v" in
	needs-bootstrap | paused | done | blocked)
		reason="backlog verdict: $v"
		break
		;;
	esac

	log="$LOGDIR/$(date +%Y%m%dT%H%M%S)-iter$i.jsonl"
	timeout -s INT --kill-after=120s "$iter_timeout" \
		claude -p "/iace-loop" --permission-mode "$mode" --permission-prompts none \
		--output-format stream-json --verbose >"$log" 2>"$log.stderr"
	rc=$?
	ran=$((ran + 1))
	final=$(jq -c 'select(.type == "result")' "$log" 2>/dev/null | tail -1)
	result=$(jq -r '.result // ""' <<<"${final:-{\}}" 2>/dev/null)
	cost=$(jq -r '.total_cost_usd // 0' <<<"${final:-{\}}" 2>/dev/null)
	is_error=$(jq -r '.is_error // false' <<<"${final:-{\}}" 2>/dev/null)
	status=$(grep -oE 'LOOP_STATUS: *(continue|waiting|paused|done|blocked)' <<<"$result" | tail -1 | awk '{print $2}')
	total=$(add "$total" "${cost:-0}")
	printf '[%s] iter %d · exit %d · status %s · cost $%.2f (total $%.2f) · last progress: %s\n' \
		"$(date +%H:%M:%S)" "$i" "$rc" "${status:-?}" "${cost:-0}" "$total" "$(last_progress)"

	if ((rc != 0)) || [[ -z "$status" || "$is_error" == "true" ]]; then
		failures=$((failures + 1))
		echo "  iteration failed ($failures in a row); log: $log"
		if ((failures >= 3)); then
			reason="3 consecutive failed iterations"
			break
		fi
	else
		failures=0
		case "$status" in
		paused | done | blocked)
			reason="iteration reported LOOP_STATUS: $status"
			break
			;;
		esac
	fi
	if [[ -n "$budget" ]] && reached "$total" "$budget"; then
		reason="budget reached (\$$total of \$$budget)"
		break
	fi
	if ((i < max)); then
		if [[ "$status" == "waiting" ]]; then
			echo "  waiting for CI on the open pull request; next check in ${wait_pause}s"
			sleep "$wait_pause"
		else
			sleep "$pause"
		fi
	fi
done
printf 'stopped: %s · iterations run: %d · total cost: $%.2f\n' "$reason" "$ran" "$total"
