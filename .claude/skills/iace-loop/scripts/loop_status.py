#!/usr/bin/env python3
"""Summarize the iace development loop state: backlog, next ready task, git, recent progress.

Usage: loop_status.py [--brief | --json]

The iace-loop skill injects this script's output at invocation time, and a failing command
would abort that injection, so the script always exits 0 and reports problems inline.
Standard library only.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]  # <root>/.claude/skills/iace-loop/scripts/
BACKLOG = ROOT / "docs" / "plan" / "BACKLOG.md"
PROGRESS = ROOT / "docs" / "plan" / "PROGRESS.md"

MILESTONE_RE = re.compile(r"^## (M\d+) · (.+?) — status: ([\w-]+)\s*$")
TASK_RE = re.compile(r"^- \[([ ~x!])\] (T-\d{4}[a-z]?) · (.+?)\s*$")
FIELD_RE = re.compile(r"^  - (\w+):\s*(.*)$")
SETTING_RE = re.compile(r"^- (\w+):\s*(\S+)")
DECISION_RE = re.compile(r"^- (D-\d+) · (.+)$")
TASK_ID_RE = re.compile(r"T-\d{4}[a-z]?")
MARKS = {" ": "todo", "~": "in-progress", "x": "done", "!": "blocked"}
MILESTONE_STATUSES = {"planned", "active", "awaiting-approval", "done"}


def parse_backlog(text: str) -> dict:
    settings: dict[str, str] = {}
    decisions: list[dict] = []
    milestones: list[dict] = []
    warnings: list[str] = []
    section = None
    task = None

    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            task = None
            m = MILESTONE_RE.match(line)
            if m:
                status = m.group(3)
                if status not in MILESTONE_STATUSES:
                    warnings.append(f"line {lineno}: unknown milestone status '{status}'")
                milestones.append({"id": m.group(1), "title": m.group(2), "status": status, "tasks": []})
                section = "milestone"
            elif line.strip() == "## Loop settings":
                section = "settings"
            elif line.strip() == "## Decisions needed":
                section = "decisions"
            else:
                section = None
            continue

        if section == "settings":
            m = SETTING_RE.match(line)
            if m:
                settings[m.group(1)] = m.group(2)
        elif section == "decisions":
            m = DECISION_RE.match(line)
            if m:
                decisions.append({"id": m.group(1), "text": m.group(2)})
        elif section == "milestone":
            m = TASK_RE.match(line)
            if m:
                task = {
                    "id": m.group(2),
                    "title": m.group(3),
                    "state": MARKS[m.group(1)],
                    "milestone": milestones[-1]["id"],
                    "depends": [],
                    "skills": [],
                    "attempts": 0,
                    "blocked": "",
                    "line": lineno,
                }
                milestones[-1]["tasks"].append(task)
                continue
            if line.startswith("- ["):
                warnings.append(f"line {lineno}: malformed task line: {line.strip()[:60]}")
                task = None
                continue
            m = FIELD_RE.match(line)
            if m and task is not None:
                key, value = m.group(1), m.group(2).strip()
                if key == "depends":
                    task["depends"] = TASK_ID_RE.findall(value)
                elif key == "skills":
                    task["skills"] = [s.strip() for s in value.split(",") if s.strip()]
                elif key == "attempts":
                    task["attempts"] = int(value) if value.isdigit() else 0
                elif key == "blocked":
                    task["blocked"] = value

    return {"settings": settings, "decisions": decisions, "milestones": milestones, "warnings": warnings}


def analyze(backlog: dict) -> dict:
    tasks = [t for ms in backlog["milestones"] for t in ms["tasks"]]
    by_id: dict[str, dict] = {}
    warnings = list(backlog["warnings"])
    for t in tasks:
        if t["id"] in by_id:
            warnings.append(f"duplicate task id {t['id']} (lines {by_id[t['id']]['line']} and {t['line']})")
        by_id[t["id"]] = t
    for t in tasks:
        for dep in t["depends"]:
            if dep not in by_id:
                warnings.append(f"{t['id']} depends on unknown task {dep}")
        if t["state"] == "blocked" and not t["blocked"]:
            warnings.append(f"{t['id']} is [!] but has no 'blocked:' reason")

    in_progress = [t for t in tasks if t["state"] == "in-progress"]
    if len(in_progress) > 1:
        warnings.append("more than one task is [~]; finish or reset all but one")

    def ready(t: dict) -> bool:
        return t["state"] == "todo" and all(by_id.get(d, {}).get("state") == "done" for d in t["depends"])

    active = [ms for ms in backlog["milestones"] if ms["status"] == "active"]
    next_ready = next((t for ms in active for t in ms["tasks"] if ready(t)), None)
    blocked = [t for t in tasks if t["state"] == "blocked"]
    complete_active = [ms["id"] for ms in active if ms["tasks"] and all(t["state"] == "done" for t in ms["tasks"])]

    if in_progress or next_ready:
        verdict = "continue"
    elif complete_active:
        verdict = "milestone-wrap-up"
    elif not active and any(ms["status"] == "awaiting-approval" for ms in backlog["milestones"]):
        verdict = "paused"
    elif backlog["milestones"] and all(ms["status"] == "done" for ms in backlog["milestones"]):
        verdict = "done"
    else:
        verdict = "blocked"

    return {
        "verdict": verdict,
        "current": in_progress[0] if in_progress else None,
        "next_ready": next_ready,
        "blocked": blocked,
        "complete_active_milestones": complete_active,
        "warnings": warnings,
    }


def git(*args: str) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def git_state() -> dict:
    if not git("rev-parse", "--is-inside-work-tree"):
        return {"repo": False}
    porcelain = git("status", "--porcelain")
    upstream = git("rev-list", "--left-right", "--count", "@{upstream}...HEAD")
    behind, ahead = (upstream.split() + ["?", "?"])[:2] if upstream else ("?", "?")
    return {
        "repo": True,
        "branch": git("rev-parse", "--abbrev-ref", "HEAD") or "(unborn)",
        "dirty_files": len(porcelain.splitlines()) if porcelain else 0,
        "last_commit": git("log", "-1", "--pretty=%h %s"),
        "ahead": ahead,
        "behind": behind,
    }


def recent_progress(limit: int = 3) -> list[str]:
    if not PROGRESS.exists():
        return []
    entries = [ln[4:].strip() for ln in PROGRESS.read_text(encoding="utf-8").splitlines() if ln.startswith("### ")]
    return entries[-limit:]


def task_line(t: dict | None) -> str:
    if not t:
        return "none"
    extra = f" (attempts {t['attempts']})" if t["attempts"] else ""
    skills = f"\n    skills: {', '.join(t['skills'])}" if t["skills"] else ""
    return f"{t['id']} · {t['title']} [{t['milestone']}]{extra}{skills}"


def main() -> None:
    as_json = "--json" in sys.argv[1:]
    report: dict = {"root": str(ROOT), "git": git_state()}

    if not BACKLOG.exists():
        report["verdict"] = "needs-bootstrap"
        if as_json:
            print(json.dumps(report, indent=2))
        else:
            print(f"iace loop status · root {ROOT}")
            print("No docs/plan/BACKLOG.md: repository not bootstrapped.")
            print("Run the iace-loop skill with argument 'bootstrap' (references/bootstrap.md).")
            g = report["git"]
            print(f"git: {'branch ' + g['branch'] if g.get('repo') else 'not a git repository yet'}")
        return

    backlog = parse_backlog(BACKLOG.read_text(encoding="utf-8"))
    analysis = analyze(backlog)
    report.update(
        settings=backlog["settings"],
        decisions=backlog["decisions"],
        milestones=[
            {
                "id": ms["id"],
                "title": ms["title"],
                "status": ms["status"],
                "done": sum(t["state"] == "done" for t in ms["tasks"]),
                "total": len(ms["tasks"]),
            }
            for ms in backlog["milestones"]
        ],
        recent_progress=recent_progress(),
        **analysis,
    )

    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return

    g = report["git"]
    print(f"iace loop status · verdict: {report['verdict']}")
    if g.get("repo"):
        print(
            f"git: {g['branch']} · dirty files: {g['dirty_files']} · ahead/behind origin: "
            f"{g['ahead']}/{g['behind']} · last: {g['last_commit'] or '(no commits)'}"
        )
    else:
        print("git: not a git repository")
    s = report["settings"]
    print("settings: " + ", ".join(f"{k}={v}" for k, v in s.items()) if s else "settings: (missing; defaults apply)")
    print("milestones: " + " | ".join(f"{m['id']} {m['status']} {m['done']}/{m['total']}" for m in report["milestones"]))
    print(f"current (in progress): {task_line(report['current'])}")
    print(f"next ready: {task_line(report['next_ready'])}")
    if report["complete_active_milestones"]:
        print("milestone wrap-up due: " + ", ".join(report["complete_active_milestones"]))
    if report["blocked"]:
        print("blocked:")
        for t in report["blocked"]:
            print(f"  - {t['id']} · {t['title']} — {t['blocked'] or '(no reason)'}")
    if report["decisions"]:
        print(f"decisions needed: {len(report['decisions'])} (see BACKLOG 'Decisions needed')")
    if report["recent_progress"]:
        print("recent progress:")
        for e in report["recent_progress"]:
            print(f"  - {e}")
    if report["warnings"]:
        print("backlog warnings:")
        for w in report["warnings"]:
            print(f"  - {w}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # never abort the skill injection
        print(f"loop_status.py failed: {type(exc).__name__}: {exc}")
        print("Read docs/plan/BACKLOG.md and docs/plan/PROGRESS.md manually.")
    sys.exit(0)
