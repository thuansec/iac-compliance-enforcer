#!/usr/bin/env python3
"""CI state of a commit from the GitHub Actions API; optionally wait until CI finishes.

Usage: ci_state.py [--sha SHA] [--wait] [--timeout SECONDS] [--interval SECONDS] [--json]

Fine-grained tokens cannot read checks or commit statuses, so `gh pr checks`, `gh run watch` and
`gh run view` (annotations) fail with HTTP 403. This script reads only workflow runs and jobs
(Actions: read) and applies the merge gate's rule (ci_problems in .claude/hooks/guard-loop.py):
the latest pull_request run of every workflow for the commit succeeded, and so did the
required_check job from .claude/loop-policy.json (ci-ok). A failed job ends the wait early.

--sha defaults to HEAD. --wait polls every 30 s for up to 540 s, which fits in one Bash call.
Exit codes: 0 passed · 1 failed · 2 pending (no run yet, or still running when the wait ended)
· 3 unknown (gh, network or token problem). Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]  # <root>/.claude/skills/iace-loop/scripts/
OK = ("success", "skipped", "neutral")
EXIT = {"passed": 0, "failed": 1, "pending": 2, "unknown": 3}


def sh(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"{args[0]} unavailable: {type(exc).__name__}"


def gh_api_list(path: str, key: str) -> tuple[list[dict] | None, str]:
    """GET a GitHub API path; return the objects listed under key, or None and the reason."""
    rc, out, err = sh(["gh", "api", path])
    if rc != 0:
        return None, (err.strip().splitlines() or ["gh api failed"])[0][:160]
    try:
        data = json.loads(out)
    except ValueError:
        return None, "the response is not JSON"
    items = data.get(key) if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None, f"the response has no '{key}' list"
    return [i for i in items if isinstance(i, dict)], ""


def required_check() -> str:
    try:
        return json.loads((ROOT / ".claude" / "loop-policy.json").read_text()).get("required_check") or "ci-ok"
    except (OSError, ValueError, AttributeError):
        return "ci-ok"


def origin_slug() -> str | None:
    rc, out, _ = sh(["git", "remote", "get-url", "origin"], timeout=10)
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", out.strip()) if rc == 0 else None
    return m.group(1) if m else None


def ci_state(slug: str, sha: str, required: str | None = None) -> dict:
    """Verdict for one commit (passed, failed, pending or unknown) with its runs, jobs and problems."""
    required = required or required_check()
    state: dict = {"sha": sha, "verdict": "unknown", "required_check": required, "required_state": "missing",
                   "runs": [], "problems": []}
    runs, err = gh_api_list(f"repos/{slug}/actions/runs?head_sha={sha}&event=pull_request&per_page=100", "workflow_runs")
    if runs is None:
        state["problems"].append(f"could not read the CI runs: {err}")
        return state
    latest: dict[str, dict] = {}
    for r in runs:  # re-runs and reopened PRs leave older runs for the same commit behind
        key = r.get("path") or r.get("name") or "?"
        rank = (r.get("run_number") or 0, r.get("run_attempt") or 0)
        if key not in latest or rank > (latest[key].get("run_number") or 0, latest[key].get("run_attempt") or 0):
            latest[key] = r
    if not latest:
        state.update(verdict="pending", problems=["no CI run for this commit yet"])
        return state
    failed = pending = False
    for _, r in sorted(latest.items()):
        run = {"id": r.get("id"), "workflow": r.get("name") or r.get("path"), "status": r.get("status"),
               "conclusion": r.get("conclusion"), "url": r.get("html_url"), "jobs": []}
        state["runs"].append(run)
        if run["status"] != "completed":
            pending = True
        elif run["conclusion"] not in OK:
            failed = True
            state["problems"].append(f"workflow {run['workflow']} concluded {run['conclusion']}")
        jobs, err = gh_api_list(f"repos/{slug}/actions/runs/{run['id']}/jobs?per_page=100", "jobs")
        if jobs is None:
            state["problems"].append(f"could not read the jobs of workflow {run['workflow']}: {err}")
            return state
        for j in jobs:
            job = {"name": j.get("name"), "status": j.get("status"), "conclusion": j.get("conclusion")}
            run["jobs"].append(job)
            if job["name"] == required:
                state["required_state"] = job["conclusion"] if job["status"] == "completed" else job["status"]
            if job["status"] != "completed":
                pending = True
            elif job["conclusion"] not in OK:
                failed = True
                state["problems"].append(f"job {job['name']} ({run['workflow']}) concluded {job['conclusion']}")
    if failed:
        state["verdict"] = "failed"
    elif pending:
        state["verdict"] = "pending"
    elif state["required_state"] != "success":
        state["verdict"] = "failed"
        state["problems"].append(f"required check '{required}' is {state['required_state']}")
    else:
        state["verdict"] = "passed"
    return state


def render(state: dict) -> str:
    lines = [f"CI for {state['sha'][:8]} (pull_request): {state['verdict']}"]
    for run in state["runs"]:
        lines.append(f"  {run['workflow']}: {run['conclusion'] or run['status']} (run {run['id']})")
        lines += [f"    {j['name']}: {j['conclusion'] or j['status']}" for j in run["jobs"]]
    lines += [f"  ! {p}" for p in state["problems"]]
    if state["verdict"] == "failed":
        bad = [r["id"] for r in state["runs"]
               if r["conclusion"] not in (None, *OK) or any(j["conclusion"] not in (None, *OK) for j in r["jobs"])]
        lines += [f"  logs: gh run view {i} --log-failed" for i in bad]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="CI state of a commit from the GitHub Actions API.")
    ap.add_argument("--sha", help="commit to check (default: HEAD)")
    ap.add_argument("--wait", action="store_true", help="poll until CI passes or fails, or the timeout")
    ap.add_argument("--timeout", type=int, default=540, help="seconds to wait (default: 540)")
    ap.add_argument("--interval", type=int, default=30, help="seconds between polls (default: 30)")
    ap.add_argument("--json", action="store_true", help="print the state as JSON")
    args = ap.parse_args()

    rc, out, _ = sh(["git", "rev-parse", "--verify", "--quiet", f"{args.sha or 'HEAD'}^{{commit}}"], timeout=10)
    sha, slug = out.strip(), origin_slug()
    if rc != 0 or not slug:
        problem = "cannot tell the GitHub repository from the origin remote" if rc == 0 else f"unknown commit {args.sha or 'HEAD'}"
        state = {"sha": args.sha or "HEAD", "verdict": "unknown", "runs": [], "problems": [problem]}
    else:
        deadline, unknown_streak, last = time.monotonic() + args.timeout, 0, ""
        while True:
            state = ci_state(slug, sha)
            unknown_streak = unknown_streak + 1 if state["verdict"] == "unknown" else 0
            if (not args.wait or state["verdict"] in ("passed", "failed") or unknown_streak >= 3
                    or time.monotonic() + args.interval > deadline):
                break
            progress = "; ".join(f"{r['workflow']} {r['status']}" for r in state["runs"]) or state["problems"][0]
            if progress != last:
                print(f"waiting: {progress}", file=sys.stderr, flush=True)
                last = progress
            time.sleep(args.interval)
    print(json.dumps(state, indent=2) if args.json else render(state))
    return EXIT[state["verdict"]]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # exit 1 would read as "CI failed"
        print(f"ci_state.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(EXIT["unknown"])
