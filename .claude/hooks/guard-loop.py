#!/usr/bin/env python3
"""PreToolUse hook (matcher: Bash): deterministic guardrails for the iace development loop.

The loop's rules live in skills and CLAUDE.md, which the model follows most of the time. The
rules below must hold every time, so they are enforced here. A blocked command exits 2 and the
reason goes to Claude; anything else exits 0.

Blocked:
  publish      git push unless docs/plan/BACKLOG.md says `push_to_remote: yes`; always: force
               pushes, remote ref deletion, --no-verify; gh commands that change GitHub state
               (`gh pr create` only when pushing is allowed); `gh auth token` (prints a secret)
  destroy      git reset --hard, git clean -f, whole-tree checkout/restore, checkout -f,
               stash drop/clear, branch -D, history rewriting; rm -r of /, ~, $HOME, the project
               root or any of its parents
  unverified   git commit unless the full quality gates passed on exactly this tree
               (.cache/gates/full.pass matches tree-fingerprint.sh); commits that only touch
               docs/plan/BACKLOG.md or PROGRESS.md need no stamp
  escape       sudo/su, downloads piped into an interpreter, terraform/tofu apply/destroy/
               import/state changes, git remote changes, git config --global/--system

Invalid hook input blocks (fail closed). An internal error in this script is reported but does
not block (exit 1): a guard bug must not lock the session out, and permissions.deny in
.claude/settings.json backs up the most destructive cases. People can always run a command
themselves with the `!` prefix, which does not go through hooks.

Tests: .claude/hooks/tests/run.sh
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROJECT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2]).resolve()
STAMP = PROJECT / ".cache" / "gates" / "full.pass"
FINGERPRINT = PROJECT / ".claude" / "skills" / "iace-quality-gates" / "scripts" / "tree-fingerprint.sh"
BACKLOG = PROJECT / "docs" / "plan" / "BACKLOG.md"
PLAN_FILES = ("docs/plan/BACKLOG.md", "docs/plan/PROGRESS.md")

OPERATORS = ("&&", "||", "|&", ";;", "|", ";", "&", "(", ")", "\n")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}
WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "env", "nice", "timeout", "stdbuf", "xargs"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class Blocked(Exception):
    pass


# --- tokenizing -------------------------------------------------------------------------------


def strip_heredocs(text: str) -> str:
    """Drop heredoc bodies: they are data (commit messages, file contents), not commands."""
    out, pending = [], []
    for line in text.split("\n"):
        if pending:
            term, dash = pending[0]
            if (line.lstrip("\t") if dash else line) == term:
                pending.pop(0)
            continue
        out.append(line)
        for m in re.finditer(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", line):
            pending.append((m.group(3), m.group(1) == "-"))
    return "\n".join(out)


def tokenize(text: str) -> list[tuple[str, str]]:
    """Split shell text into ('word', value) and ('op', operator) tokens.

    Handles quotes, backslash escapes, comments and the operators that separate commands.
    $(...) and backtick contents stay inside their word; extract_substitutions() handles them.
    """
    tokens: list[tuple[str, str]] = []
    word, in_word, drop_next, i, n = [], False, False, 0, len(text)

    def flush() -> None:
        nonlocal word, in_word, drop_next
        if in_word:
            if drop_next:  # the target of a redirection is a file, not an argument
                drop_next = False
            else:
                tokens.append(("word", "".join(word)))
        word, in_word = [], False

    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                word.append(text[i + 1])
                in_word = True
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            word.append(text[i + 1 : j])
            in_word, i = True, j + 1
            continue
        if c == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\$`':
                    buf.append(text[j + 1])
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            word.append("".join(buf))
            in_word, i = True, j + 1
            continue
        if c == "#" and not in_word:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in " \t":
            flush()
            i += 1
            continue
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if op:
            flush()
            tokens.append(("op", op))
            i += len(op)
            continue
        if c in "<>":  # redirection: drop a leading fd number and the target word
            if in_word and "".join(word).isdigit():
                word, in_word = [], False
            flush()
            i += 1
            while i < n and text[i] in "<>&":
                i += 1
            while i < n and text[i] in " \t":
                i += 1
            if i < n and text[i].isdigit() and text[i - 1] == "&":
                while i < n and text[i].isdigit():
                    i += 1
            else:
                drop_next = True
            continue
        word.append(c)
        in_word = True
        i += 1
    flush()
    return tokens


def extract_substitutions(text: str) -> tuple[str, list[str]]:
    """Pull out $(...) and `...` bodies so they are checked as commands of their own."""
    inner: list[str] = []
    while True:
        m = re.search(r"\$\(([^()]*)\)", text)
        if not m:
            break
        inner.append(m.group(1))
        text = text[: m.start()] + " __subst__ " + text[m.end() :]
    for m in re.finditer(r"`([^`]*)`", text):
        inner.append(m.group(1))
    text = re.sub(r"`[^`]*`", " __subst__ ", text)
    return text, inner


def commands(text: str) -> list[tuple[list[str], str]]:
    """Return simple commands as (argv, operator-before-it), including nested ones."""
    text, nested = extract_substitutions(strip_heredocs(text))
    result: list[tuple[list[str], str]] = []
    argv: list[str] = []
    prev_op = ""
    for kind, value in tokenize(text):
        if kind == "op":
            if argv:
                result.append((argv, prev_op))
            argv, prev_op = [], value
        else:
            argv.append(value)
    if argv:
        result.append((argv, prev_op))
    for body in nested:
        result.extend(commands(body))
    return result


def unwrap(argv: list[str]) -> list[str]:
    """Strip env assignments and wrapper programs (env, timeout, nohup, ...)."""
    i = 0
    while i < len(argv):
        word = argv[i]
        if ASSIGNMENT.match(word):
            i += 1
            continue
        base = os.path.basename(word)
        if base in ("sudo", "doas", "su"):
            raise Blocked(f"{base} is not allowed: the loop never escalates privileges")
        if base in WRAPPERS:
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or ASSIGNMENT.match(argv[i])):
                takes_value = argv[i] in ("-n", "-s", "-k", "-u", "-i", "-o", "-e", "--signal", "--kill-after")
                i += 2 if takes_value else 1
            if base == "timeout" and i < len(argv) and re.match(r"^\d+(\.\d+)?[smhd]?$", argv[i]):
                i += 1
            continue
        break
    return argv[i:]


# --- policy -----------------------------------------------------------------------------------


def push_allowed() -> bool:
    try:
        text = BACKLOG.read_text(encoding="utf-8")
    except OSError:
        return False
    m = re.search(r"^- push_to_remote:\s*(\S+)", text, re.M)
    return bool(m and m.group(1).lower() in ("yes", "true"))


def is_project_repo(directory: Path) -> bool:
    try:
        top = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(top) and Path(top).resolve() == PROJECT


def check_commit_stamp(repo: Path) -> None:
    if not is_project_repo(repo):
        return
    status = subprocess.run(
        ["git", "-C", str(PROJECT), "status", "--porcelain", "--untracked-files=all", "--", "."]
        + [f":(exclude){p}" for p in PLAN_FILES],
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    if not status:
        return  # nothing outside the plan files: grooming or progress-only commit
    fp = subprocess.run(["bash", str(FINGERPRINT), str(PROJECT)], capture_output=True, text=True, timeout=60)
    current = fp.stdout.strip()
    try:
        stamp = STAMP.read_text(encoding="utf-8").strip()
    except OSError:
        stamp = ""
    if fp.returncode != 0 or not current or current != stamp:
        raise Blocked(
            "git commit blocked: the full quality gates have not passed on this exact tree. Run "
            "`bash .claude/skills/iace-quality-gates/scripts/gates.sh full` (it records "
            ".cache/gates/full.pass on success), then commit without changing files in between "
            "(BACKLOG.md and PROGRESS.md excepted)."
        )


def check_git(args: list[str], cwd: Path) -> None:
    i, repo = 0, cwd
    while i < len(args) and args[i].startswith("-"):
        flag = args[i]
        if flag == "-C" and i + 1 < len(args):
            repo = (repo / args[i + 1]).resolve()
            i += 2
        elif flag in ("-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(args):
            i += 2
        else:
            i += 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1 :]
    if "--no-verify" in rest or (sub == "commit" and "-n" in rest):
        raise Blocked(f"git {sub} --no-verify is not allowed: verification is never skipped")
    if sub == "push":
        if "--dry-run" in rest or "-n" in rest:
            return  # changes nothing on the remote
        forced = any(
            a in ("-f", "--force", "--mirror", "-d", "--delete", "--prune", "--force-if-includes")
            or a.startswith("--force-with-lease") or (not a.startswith("-") and a[:1] in "+:")
            for a in rest
        )
        if forced:
            raise Blocked("force pushes and remote ref deletion are never allowed from Claude")
        if not push_allowed():
            raise Blocked(
                "git push blocked: docs/plan/BACKLOG.md loop settings say push_to_remote: no. "
                "A human publishes (run `! git push` yourself), or set push_to_remote: yes."
            )
    elif sub == "commit":
        check_commit_stamp(repo)
    elif sub == "reset" and "--hard" in rest:
        raise Blocked("git reset --hard discards work; use `git stash push -u -m ...` instead")
    elif sub == "clean" and any(a == "--force" or (re.match(r"^-[a-zA-Z]+$", a) and "f" in a) for a in rest):
        raise Blocked("git clean -f deletes untracked work; nothing in the loop needs it")
    elif sub in ("checkout", "restore"):
        whole_tree = any(a in (".", ":/", "./") for a in rest)
        unstage_only = sub == "restore" and ("--staged" in rest or "-S" in rest) and not (
            "--worktree" in rest or "-W" in rest
        )
        if (whole_tree and not unstage_only) or (sub == "checkout" and ("-f" in rest or "--force" in rest)):
            raise Blocked(f"git {sub} on the whole tree discards work; use `git stash push -u` instead")
    elif sub == "stash" and rest[:1] and rest[0] in ("drop", "clear"):
        raise Blocked("git stash drop/clear destroys saved attempts; leave stashes for a human")
    elif sub == "branch" and (
        any(re.match(r"^-[a-zA-Z]*D", a) for a in rest)
        or ({"-d", "--delete"} & set(rest) and {"-f", "--force"} & set(rest))
    ):
        raise Blocked("git branch -D can lose commits; leave branch deletion to a human")
    elif sub in ("filter-branch", "filter-repo") or (sub == "reflog" and rest[:1] and rest[0] in ("expire", "delete")):
        raise Blocked(f"git {sub} rewrites or prunes history; never from the loop")
    elif sub == "update-ref" and "-d" in rest:
        raise Blocked("git update-ref -d deletes refs; never from the loop")
    elif sub == "remote" and rest[:1] and rest[0] in ("add", "remove", "rm", "rename", "set-url", "set-head", "prune"):
        raise Blocked("changing git remotes is a human decision")
    elif sub == "config" and any(a in ("--global", "--system") for a in rest):
        raise Blocked("git config --global/--system changes this machine, not the repository")


GH_READ = {
    "pr": {"list", "view", "status", "diff", "checks"},
    "release": {"list", "view", "download"},
    "repo": {"view", "list", "clone", "set-default"},
    "secret": {"list"},
    "variable": {"list", "get"},
    "workflow": {"list", "view"},
    "run": {"list", "view", "watch", "download"},
    "issue": {"list", "view", "status"},
    "label": {"list"},
    "ruleset": {"list", "view", "check"},
    "auth": {"status"},
    "cache": {"list"},
}


def check_gh(args: list[str]) -> None:
    if not args:
        return
    group, sub = args[0], (args[1] if len(args) > 1 else "")
    if group == "api":
        method = "GET"
        for j, a in enumerate(args):
            if a in ("-X", "--method") and j + 1 < len(args):
                method = args[j + 1].upper()
            elif a.startswith("--method="):
                method = a.split("=", 1)[1].upper()
        has_fields = any(a in ("-f", "-F", "--field", "--raw-field", "--input") or a.startswith(("--field=", "--raw-field=")) for a in args)
        endpoint = next((a for a in args[1:] if not a.startswith("-") and "=" not in a), "")
        if endpoint.lstrip("/") == "graphql":
            if "mutation" in " ".join(args):
                raise Blocked("GraphQL mutations change GitHub state; a human runs them")
            return
        if method not in ("GET", "HEAD") or (has_fields and method == "GET" and not any(a in ("-X", "--method") or a.startswith("--method=") for a in args)):
            raise Blocked("gh api writes change GitHub state; a human runs them (use `! gh api ...`)")
        return
    if group == "auth" and sub == "token":
        raise Blocked("gh auth token prints a credential; never run it")
    allowed = GH_READ.get(group)
    if allowed is None:
        return  # not a state-changing group we know about
    if sub in allowed or sub in ("", "--help", "-h"):
        return
    if group == "pr" and sub == "create" and push_allowed():
        return
    raise Blocked(f"gh {group} {sub} changes GitHub state; a human runs it (use `! gh {group} {sub} ...`)")


def check_terraform(prog: str, args: list[str]) -> None:
    rest = [a for a in args if not a.startswith("-chdir")]
    sub = next((a for a in rest if not a.startswith("-")), "")
    dangerous = {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh"}
    if sub in dangerous or (sub == "state" and any(a in ("rm", "mv", "push", "replace-provider") for a in rest)):
        raise Blocked(f"{prog} {sub} changes real infrastructure; the loop never does that")


def check_rm(args: list[str], cwd: Path) -> None:
    recursive = any(a in ("-r", "-R", "--recursive") or re.match(r"^-[a-zA-Z]*[rR]", a) for a in args)
    if not recursive:
        return
    home = Path.home().resolve()
    for target in (a for a in args if not a.startswith("-")):
        if target in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "*", ".", "./", "..", "../", "../*"):
            raise Blocked(f"rm -r {target} is too broad; delete specific paths inside the repository")
        if "$" in target or "~" in target:
            continue
        path = (cwd / target).resolve()
        if path in (Path("/"), home) or path == PROJECT or path in PROJECT.parents or path == PROJECT / ".git":
            raise Blocked(f"rm -r {target} would delete the project, its git data or a parent directory")


def check(argv: list[str], prev_op: str, prev_prog: str, cwd: Path) -> None:
    argv = unwrap(argv)
    if not argv:
        return
    prog = os.path.basename(argv[0])
    args = argv[1:]
    if prog in SHELLS and "-c" in args:
        script = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
        evaluate(script, cwd)
        return
    if prev_op in ("|", "|&") and prog in INTERPRETERS and prev_prog in ("curl", "wget"):
        raise Blocked("piping a download into an interpreter runs unreviewed code; download, inspect, then run")
    if prog == "git":
        check_git(args, cwd)
    elif prog == "gh":
        check_gh(args)
    elif prog in ("terraform", "tofu"):
        check_terraform(prog, args)
    elif prog == "rm":
        check_rm(args, cwd)


def evaluate(text: str, cwd: Path) -> None:
    prev_prog = ""
    for argv, prev_op in commands(text):
        core = unwrap(list(argv)) if argv else []
        if core and os.path.basename(core[0]) == "cd":
            target = core[1] if len(core) > 1 else str(Path.home())
            if "$" not in target and "~" not in target:
                cwd = (cwd / target).resolve()
            elif target.startswith("~"):
                cwd = Path(os.path.expanduser(target)).resolve()
        check(argv, prev_op, prev_prog, cwd)
        prev_prog = os.path.basename(core[0]) if core else ""


def main() -> int:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        tool_input = data.get("tool_input") or {}
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    except (ValueError, AttributeError):
        print("BLOCKED by guard-loop.py: the hook input is not valid JSON", file=sys.stderr)
        return 2
    if not command:
        return 0
    cwd = Path(data.get("cwd") or PROJECT)
    try:
        evaluate(command, cwd)
    except Blocked as reason:
        print(f"BLOCKED by .claude/hooks/guard-loop.py: {reason}", file=sys.stderr)
        print("Do not work around this guard with other syntax; fix the cause or record a blocker.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a guard bug must not lock the session out
        print(f"guard-loop.py internal error (command allowed): {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
