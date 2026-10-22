"""Write the job summary, workflow annotations and blocking-count for the iace GitHub Action.

Usage: python3 -I report.py SARIF_FILE

Reads the SARIF that `iace scan -o sarif` wrote and the environment the action sets:
GITHUB_STEP_SUMMARY and GITHUB_OUTPUT (files GitHub provides), IACE_EXIT_CODE (the scan's exit
code) and IACE_ANNOTATIONS ("true" prints ::error/::warning/::notice lines on stdout).

This is the interim reporter of ADR 0053: once iace writes Markdown and annotations itself
(`-o markdown`, `-o github`, T-0304), the action uses those and this script goes. Finding
messages and paths come from the scanned Terraform, so every value is escaped for the workflow
command or Markdown it lands in. Standard library only; the runner's python3 runs it.
"""

import json
import os
import sys
import urllib.parse

MAX_ROWS = 100
LEVEL_COMMAND = {"error": "error", "warning": "warning", "note": "notice", "none": "notice"}


def escape_data(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value):
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def escape_markdown(value):
    value = " ".join(value.split())
    for raw, safe in (("\\", "\\\\"), ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("`", "\\`"),
                      ("[", "\\["), ("]", "\\]"), ("*", "\\*"), ("_", "\\_")):
        value = value.replace(raw, safe)
    return value


def load_run(path):
    """Returns the single run of the SARIF file, None when it is missing or empty."""
    try:
        with open(path, encoding="utf-8") as f:
            data = f.read()
    except FileNotFoundError:
        return None
    if not data.strip():
        return None
    runs = json.loads(data)["runs"]
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ValueError("want exactly one SARIF run")
    run = runs[0]
    if not isinstance(run.get("results", []), list):
        raise ValueError("results is not a list")
    return run


def location(result):
    """Returns (repository-relative path, line), either None when the result has none."""
    for loc in result.get("locations") or []:
        physical = loc.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if uri:
            line = (physical.get("region") or {}).get("startLine")
            return urllib.parse.unquote(uri), line if isinstance(line, int) else None
    return None, None


def excepted(result):
    return any(s.get("status", "accepted") == "accepted" for s in result.get("suppressions") or [])


def annotation(result):
    command = LEVEL_COMMAND.get(result.get("level", "warning"), "warning")
    props = []
    path, line = location(result)
    if path:
        props.append("file=" + escape_property(path))
        if line:
            props.append("line=%d" % line)
    props.append("title=" + escape_property(str(result.get("ruleId", "iace"))))
    message = escape_data(str((result.get("message") or {}).get("text", "")))
    return "::%s %s::%s" % (command, ",".join(props), message)


def summary(run, exit_code):
    lines = ["## iace", ""]
    if exit_code == "":
        return "\n".join(lines + ["**The scan did not run:** an input was refused or iace could not be installed. See the job log.", ""])
    if exit_code not in ("0", "1"):
        lines += ["**The scan could not be trusted (exit code %s):** a policy, parse or "
                  "configuration error, a timeout or no Terraform found. See the job log." % escape_markdown(exit_code), ""]
    if run is None:
        return "\n".join(lines) + "\n"
    results = run.get("results", [])
    open_results = [r for r in results if not excepted(r)]
    blocking = sum(1 for r in open_results if r.get("level") == "error")
    if exit_code == "0":
        lines.append("Passed (exit code 0): no open finding at or above high.")
    elif exit_code == "1":
        lines.append("Failed (exit code 1): %d open finding(s) at or above high." % blocking)
    counts = {}
    for r in open_results:
        counts[r.get("level", "warning")] = counts.get(r.get("level", "warning"), 0) + 1
    parts = ["%d %s" % (counts[level], level) for level in ("error", "warning", "note", "none") if level in counts]
    parts.append("%d excepted" % (len(results) - len(open_results)))
    lines += ["", "Open findings: " + ", ".join(parts) + ".", ""]
    if open_results:
        lines += ["| Level | Rule | Location | Message |", "|---|---|---|---|"]
        for r in open_results[:MAX_ROWS]:
            path, line = location(r)
            where = "%s:%d" % (path, line) if path and line else (path or "")
            lines.append("| %s | %s | %s | %s |" % (
                escape_markdown(str(r.get("level", ""))), escape_markdown(str(r.get("ruleId", ""))),
                escape_markdown(where), escape_markdown(str((r.get("message") or {}).get("text", "")))))
        if len(open_results) > MAX_ROWS:
            lines.append("")
            lines.append("Only the first %d of %d open findings are listed; the SARIF file has all of them."
                         % (MAX_ROWS, len(open_results)))
        lines.append("")
    notes = []
    for inv in run.get("invocations") or []:
        for n in inv.get("toolExecutionNotifications") or []:
            notes.append(escape_markdown(str((n.get("message") or {}).get("text", ""))))
    if notes:
        lines += ["**Not fully checked:**", ""] + ["- " + n for n in notes] + [""]
    return "\n".join(lines) + "\n"


def append(path, text):
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def main(argv):
    if len(argv) != 2:
        print("usage: report.py SARIF_FILE", file=sys.stderr)
        return 2
    exit_code = os.environ.get("IACE_EXIT_CODE", "")
    # Build everything before writing anything, so a malformed report publishes no partial result.
    try:
        # Without a scan, a SARIF file in the workspace is stale or came with the pull request.
        run = load_run(argv[1]) if exit_code else None
        text = summary(run, exit_code)
        if run is not None:
            results = run.get("results", [])
            blocking = sum(1 for r in results if not excepted(r) and r.get("level") == "error")
            notes = [annotation(r) for r in results if not excepted(r)]
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        append(os.environ.get("GITHUB_STEP_SUMMARY"), "## iace\n\n**The SARIF report could not be read.** See the job log.\n")
        print("::error title=iace::the SARIF report could not be read: %s" % escape_data(str(e)), file=sys.stderr)
        return 1
    append(os.environ.get("GITHUB_STEP_SUMMARY"), text)
    if run is None:
        return 0
    append(os.environ.get("GITHUB_OUTPUT"), "blocking-count=%d\n" % blocking)
    if os.environ.get("IACE_ANNOTATIONS") == "true":
        for line in notes:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
