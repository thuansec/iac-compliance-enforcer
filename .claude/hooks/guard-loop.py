#!/usr/bin/env python3
"""PreToolUse hook (matchers: Bash, and Write|Edit|MultiEdit|NotebookEdit): deterministic
guardrails for the iace development loop.

Policy lives in .claude/loop-policy.json (git workflow, push/PR/merge permissions, live API
calls). It is a harness file, so the loop cannot change its own permissions.

Decisions: exit 2 blocks (reason on stderr, shown to Claude); a JSON "ask" on stdout means a
human must approve (headless runs with --permission-prompts none deny it); exit 0 allows.

Bash, blocked:
  branches    commits on the default branch (pull-request workflow); pushes to the default
              branch, of tags, of --all, or of any branch other than the one checked out; force
              pushes and remote ref deletion; pushing with uncommitted changes or content the full
              gates did not check; git switch/checkout that discards changes
  pr          gh pr create unless open_pull_requests; gh pr merge unless merge_pull_requests,
              with the policy merge method and --match-head-commit, for a PR that is open, not a
              draft, conflict-free, up to date with the default branch and fully green (the
              latest run of every workflow and the required_check job passed, read from the
              Actions API; nothing failing or pending; unreadable or unexpected data blocks);
              --admin always; --auto unless auto_merge
  destroy     git reset --hard, clean -f, whole-tree checkout/restore, stash drop/clear,
              branch -D, history rewriting; rm -r of /, ~, $HOME, the project or its parents
  unverified  git commit unless the full gates passed on exactly this content
              (.cache/gates/full.pass == tree-fingerprint.sh); plan-only commits excepted
  escape      sudo/su, downloads piped into an interpreter, terraform/tofu apply, destroy,
              import or state changes, git remote changes, git config --global/--system, GitHub
              writes through gh (api POST/PUT/PATCH/DELETE, releases, repos, secrets, ...),
              gh auth token
Bash, needs a human:
  harness     writing to .claude/** or CLAUDE.md (redirections, cp/mv/rm/sed -i/tee/chmod/...)
Write/Edit/MultiEdit/NotebookEdit, needs a human:
  harness     any file under .claude/ or CLAUDE.md

Invalid hook input blocks (fail closed). An internal error is reported but does not block (exit
1), so a guard bug cannot lock the session out; permissions.deny backs up the worst cases. People
can always run a command themselves with the `!` prefix, which bypasses hooks.

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
POLICY_FILE = PROJECT / ".claude" / "loop-policy.json"
STAMP = PROJECT / ".cache" / "gates" / "full.pass"
FINGERPRINT = PROJECT / ".claude" / "skills" / "iace-quality-gates" / "scripts" / "tree-fingerprint.sh"
PLAN_FILES = ("docs/plan/BACKLOG.md", "docs/plan/PROGRESS.md")

DEFAULT_POLICY = {  # used for missing keys; a missing or broken file grants no push, PR or merge
    "git_workflow": "pull-request",
    "default_branch": "main",
    "push_feature_branches": False,
    "open_pull_requests": False,
    "merge_pull_requests": False,
    "merge_method": "squash",
    "auto_merge": False,
    "required_check": "ci-ok",
    "live_api_calls": False,
}

OPERATORS = ("&&", "||", "|&", ";;", "|", ";", "&", "(", ")", "\n")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}
WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "env", "nice", "timeout", "stdbuf", "xargs"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
UNRESOLVED = "\x00"


class Blocked(Exception):
    pass


ASKS: list[str] = []


def load_policy() -> dict:
    policy = dict(DEFAULT_POLICY)
    try:
        data = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            policy.update({k: v for k, v in data.items() if k in DEFAULT_POLICY})
    except (OSError, ValueError):
        pass
    return policy


POLICY = load_policy()


def run(args: list[str], cwd: Path | None = None, timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


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
    """Split shell text into ('word', v), ('redir', target) and ('op', operator) tokens.

    Handles quotes, backslash escapes and comments. Output redirection targets are kept as
    'redir' tokens; input redirections, heredoc markers and fd duplications are dropped.
    """
    tokens: list[tuple[str, str]] = []
    word: list[str] = []
    in_word, pending, i, n = False, "", 0, len(text)  # pending: "" | "redir" | "drop"

    def flush() -> None:
        nonlocal word, in_word, pending
        if in_word:
            value = "".join(word)
            if pending == "redir":
                tokens.append(("redir", value))
            elif pending != "drop":
                tokens.append(("word", value))
            pending = ""
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
        if c in "<>":
            if in_word and "".join(word).isdigit():  # fd number such as the 2 in 2>&1
                word, in_word = [], False
            flush()
            start = i
            while i < n and text[i] in "<>|":
                i += 1
            op = text[start:i]
            if i < n and text[i] == "&":  # >&2, 2>&1: fd duplication, no file target
                i += 1
                while i < n and text[i].isdigit():
                    i += 1
                continue
            pending = "redir" if ">" in op else "drop"
            continue
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if op:
            if op == "&" and i + 1 < n and text[i + 1] == ">":  # &> file
                flush()
                i += 2
                pending = "redir"
                continue
            flush()
            tokens.append(("op", op))
            i += len(op)
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


def commands(text: str) -> list[tuple[list[str], str, list[str]]]:
    """Return simple commands as (argv, operator-before-it, output-redirection-targets)."""
    text, nested = extract_substitutions(strip_heredocs(text))
    result: list[tuple[list[str], str, list[str]]] = []
    argv: list[str] = []
    redirs: list[str] = []
    prev_op = ""
    for kind, value in tokenize(text):
        if kind == "op":
            if argv or redirs:
                result.append((argv, prev_op, redirs))
            argv, redirs, prev_op = [], [], value
        elif kind == "redir":
            redirs.append(value)
        else:
            argv.append(value)
    if argv or redirs:
        result.append((argv, prev_op, redirs))
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


def expand(value: str, env: dict[str, str]) -> str:
    """Expand $VAR and ${VAR} from assignments seen earlier in the command or a few safe env vars."""

    def sub(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        if name in env:
            return env[name]
        if name in ("HOME", "PWD", "TMPDIR", "USER"):
            return os.environ.get(name, UNRESOLVED)
        return UNRESOLVED

    value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", sub, value)
    if value.startswith("~"):
        value = os.path.expanduser(value)
    return value


def resolve(path: str, cwd: Path | None, env: dict[str, str]) -> Path | None:
    value = expand(path, env)
    if UNRESOLVED in value or "$" in value:
        return None
    base = cwd or PROJECT
    return (base / value).resolve()


# --- policy helpers ---------------------------------------------------------------------------


def is_project_repo(directory: Path | None) -> bool:
    if directory is None:
        return True  # unknown directory: assume the project (conservative)
    rc, top = run(["git", "-C", str(directory), "rev-parse", "--show-toplevel"], timeout=10)
    return rc == 0 and bool(top) and Path(top).resolve() == PROJECT


def current_branch(repo: Path | None) -> str | None:
    rc, out = run(["git", "-C", str(repo or PROJECT), "rev-parse", "--abbrev-ref", "HEAD"], timeout=10)
    return out if rc == 0 and out and out != "HEAD" else None


def fingerprint_matches_stamp() -> bool:
    rc, current = run(["bash", str(FINGERPRINT), str(PROJECT)], timeout=60)
    try:
        stamp = STAMP.read_text(encoding="utf-8").strip()
    except OSError:
        stamp = ""
    return rc == 0 and bool(current) and current == stamp


def changes_outside_plan() -> str:
    _, out = run(
        ["git", "-C", str(PROJECT), "status", "--porcelain", "--untracked-files=all", "--", "."]
        + [f":(exclude){p}" for p in PLAN_FILES]
    )
    return out


def is_harness(path: Path) -> bool:
    claude_dir = PROJECT / ".claude"
    return path == PROJECT / "CLAUDE.md" or path == claude_dir or claude_dir in path.parents


def check_harness_path(raw: str, cwd: Path | None, env: dict[str, str], verb: str) -> None:
    path = resolve(raw, cwd, env)
    if path is None:
        if ".claude" in raw or "CLAUDE.md" in raw:
            ASKS.append(f"{verb} {raw}")
        return
    if is_harness(path):
        ASKS.append(f"{verb} {path.relative_to(PROJECT) if PROJECT in path.parents else path}")


def origin_slug() -> str | None:
    _, url = run(["git", "-C", str(PROJECT), "remote", "get-url", "origin"], timeout=10)
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else None


# --- git --------------------------------------------------------------------------------------


def check_git(args: list[str], cwd: Path | None, env: dict[str, str]) -> None:
    i, repo = 0, cwd
    while i < len(args) and args[i].startswith("-"):
        flag = args[i]
        if flag == "-C" and i + 1 < len(args):
            repo = resolve(args[i + 1], repo, env)
            i += 2
        elif flag in ("-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(args):
            i += 2
        else:
            i += 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1 :]
    if "--help" in rest or "-h" in rest:
        return
    project = is_project_repo(repo)
    default = POLICY["default_branch"]
    if "--no-verify" in rest or (sub == "commit" and "-n" in rest):
        raise Blocked(f"git {sub} --no-verify is not allowed: verification is never skipped")

    if sub == "commit":
        if not project:
            return
        if POLICY["git_workflow"] == "pull-request" and current_branch(repo) in (default, None):
            raise Blocked(
                f"commits never go to {default} directly (pull-request workflow). Create a feature "
                f"branch first: git switch -c <type>/T-xxxx-<slug>"
            )
        if changes_outside_plan() and not fingerprint_matches_stamp():
            raise Blocked(
                "git commit blocked: the full quality gates have not passed on this exact content. "
                "Run `bash .claude/skills/iace-quality-gates/scripts/gates.sh full` (it records "
                ".cache/gates/full.pass on success), then commit without changing files in between "
                "(BACKLOG.md and PROGRESS.md excepted)."
            )
    elif sub == "push":
        check_push(rest, repo, project)
    elif sub == "reset" and "--hard" in rest:
        raise Blocked("git reset --hard discards work; use `git stash push -u -m ...` instead")
    elif sub == "clean" and any(a == "--force" or (re.match(r"^-[a-zA-Z]+$", a) and "f" in a) for a in rest):
        raise Blocked("git clean -f deletes untracked work; nothing in the loop needs it")
    elif sub == "switch" and any(a in ("-f", "--force", "--discard-changes") for a in rest):
        raise Blocked("git switch --discard-changes/--force discards work; commit or stash first")
    elif sub in ("checkout", "restore"):
        whole_tree = any(a in (".", ":/", "./") for a in rest)
        unstage_only = sub == "restore" and ("--staged" in rest or "-S" in rest) and not (
            "--worktree" in rest or "-W" in rest
        )
        if (whole_tree and not unstage_only) or (sub == "checkout" and ("-f" in rest or "--force" in rest)):
            raise Blocked(f"git {sub} on the whole tree discards work; use `git stash push -u` instead")
        for a in rest:
            if not a.startswith("-"):
                check_harness_path(a, repo, env, f"git {sub}")
    elif sub in ("rm", "mv"):
        for a in rest:
            if not a.startswith("-"):
                check_harness_path(a, repo, env, f"git {sub}")
    elif sub == "stash" and rest[:1] and rest[0] in ("drop", "clear"):
        raise Blocked("git stash drop/clear destroys saved attempts; leave stashes for a human")
    elif sub == "branch" and (
        any(re.match(r"^-[a-zA-Z]*D", a) for a in rest)
        or ({"-d", "--delete"} & set(rest) and {"-f", "--force"} & set(rest))
    ):
        raise Blocked("git branch -D can lose commits; leave branch deletion to a human (or gh pr merge -d)")
    elif sub in ("filter-branch", "filter-repo") or (sub == "reflog" and rest[:1] and rest[0] in ("expire", "delete")):
        raise Blocked(f"git {sub} rewrites or prunes history; never from the loop")
    elif sub == "update-ref" and "-d" in rest:
        raise Blocked("git update-ref -d deletes refs; never from the loop")
    elif sub == "remote" and rest[:1] and rest[0] in ("add", "remove", "rm", "rename", "set-url", "set-head", "prune"):
        raise Blocked("changing git remotes is a human decision")
    elif sub == "config" and any(a in ("--global", "--system") for a in rest):
        raise Blocked("git config --global/--system changes this machine, not the repository")


def check_push(rest: list[str], repo: Path | None, project: bool) -> None:
    if "--dry-run" in rest or "-n" in rest:
        return  # changes nothing on the remote
    default = POLICY["default_branch"]
    if any(
        a in ("-f", "--force", "--mirror", "-d", "--delete", "--prune", "--force-if-includes")
        or a.startswith("--force-with-lease")
        or (not a.startswith("-") and a[:1] in "+:")
        for a in rest
    ):
        raise Blocked("force pushes and remote ref deletion are never allowed from Claude")
    if any(a in ("--tags", "--follow-tags", "--all") for a in rest) or any("refs/tags/" in a for a in rest):
        raise Blocked("pushing tags or all branches is a release decision for a human")
    if not POLICY["push_feature_branches"]:
        raise Blocked("loop policy (.claude/loop-policy.json) does not allow pushing; a human publishes (`! git push`)")
    positional, skip = [], False
    for a in rest:
        if skip:
            skip = False
        elif a in ("-o", "--push-option", "--receive-pack", "--exec", "--repo"):
            skip = True
        elif not a.startswith("-"):
            positional.append(a)
    branch = current_branch(repo)
    targets = []
    for spec in positional[1:] or [""]:
        src, _, dst = spec.partition(":")
        name = (dst or src or branch or "").removeprefix("refs/heads/")
        targets.append(branch if name in ("HEAD", "@") else name)
    for target in targets:
        if not target or not branch:
            raise Blocked("cannot tell which branch this pushes; check out the feature branch and `git push -u origin HEAD`")
        if target in (default, "master"):
            raise Blocked(f"{default} only changes through merged pull requests; push your feature branch instead")
        if target != branch:
            raise Blocked(f"push only the branch you have checked out ({branch}), after the gates passed on it")
    if project:
        if run(["git", "-C", str(PROJECT), "status", "--porcelain", "--untracked-files=all"])[1]:
            raise Blocked("commit everything (including BACKLOG.md and PROGRESS.md) before pushing")
        if not fingerprint_matches_stamp():
            raise Blocked(
                "push blocked: the full gates have not passed on this content (for example after merging "
                f"origin/{default}). Run `gates.sh full`, commit, then push."
            )


# --- gh ---------------------------------------------------------------------------------------

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
MERGE_FLAGS = {"squash": ("-s", "--squash"), "merge": ("-m", "--merge"), "rebase": ("-r", "--rebase")}


def option_value(args: list[str], name: str) -> str | None:
    for j, a in enumerate(args):
        if a == name and j + 1 < len(args):
            return args[j + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def check_gh(args: list[str]) -> None:
    if not args or args[0] in ("help", "version", "--version") or "--help" in args or "-h" in args:
        return
    group, sub = args[0], (args[1] if len(args) > 1 else "")
    if group == "api":
        method = (option_value(args, "-X") or option_value(args, "--method") or "").upper()
        has_fields = any(a in ("-f", "-F", "--field", "--raw-field", "--input") or a.startswith(("--field=", "--raw-field=")) for a in args)
        endpoint = next((a for a in args[1:] if not a.startswith("-") and "=" not in a), "")
        if endpoint.lstrip("/") == "graphql":
            if "mutation" in " ".join(args):
                raise Blocked("GraphQL mutations change GitHub state; a human runs them")
            return
        if method not in ("", "GET", "HEAD") or (has_fields and not method):
            raise Blocked("gh api writes change GitHub state; a human runs them (use `! gh api ...`)")
        return
    if group == "auth" and sub == "token":
        raise Blocked("gh auth token prints a credential; never run it")
    if group == "pr" and sub == "create":
        if not POLICY["open_pull_requests"]:
            raise Blocked("loop policy does not allow opening pull requests; a human opens them")
        return
    if group == "pr" and sub == "merge":
        check_pr_merge(args[2:])
        return
    allowed = GH_READ.get(group)
    if allowed is None or sub in allowed or sub == "":
        return
    raise Blocked(f"gh {group} {sub} changes GitHub state; a human runs it (use `! gh {group} {sub} ...`)")


def check_pr_merge(rest: list[str]) -> None:
    default, method = POLICY["default_branch"], POLICY["merge_method"]
    if "--admin" in rest:
        raise Blocked("gh pr merge --admin bypasses the merge requirements; never")
    if not POLICY["merge_pull_requests"]:
        raise Blocked("loop policy: a human merges pull requests")
    repo_opt = option_value(rest, "-R") or option_value(rest, "--repo")
    if repo_opt and repo_opt != origin_slug():
        raise Blocked("merge pull requests of this repository only")
    others = [f for m, fl in MERGE_FLAGS.items() if m != method for f in fl]
    if not any(f in rest for f in MERGE_FLAGS.get(method, ())) or any(f in rest for f in others):
        raise Blocked(f"merge with --{method} only (loop policy merge_method)")
    if "--auto" in rest:
        if not POLICY["auto_merge"]:
            raise Blocked(
                "--auto needs server-side protection (a ruleset requiring the CI check); loop policy "
                "auto_merge is false. Wait for the checks, then merge with --match-head-commit."
            )
        return  # GitHub enforces the required checks before merging
    sha = option_value(rest, "--match-head-commit")
    if not sha:
        raise Blocked("pass --match-head-commit <sha> so the merge is pinned to the verified head")
    positional, skip = [], False
    for a in rest:
        if skip:
            skip = False
        elif a in ("--match-head-commit", "-t", "--subject", "-b", "--body", "-F", "--body-file", "-A", "--author-email", "-R", "--repo"):
            skip = True
        elif not a.startswith("-"):
            positional.append(a)
    try:
        problems = merge_problems(positional[:1], sha, default)
    except Exception as exc:  # unlike the rest of the guard, the merge gate fails closed
        problems = [f"could not verify the pull request ({type(exc).__name__}: {exc})"]
    if problems:
        raise Blocked("gh pr merge blocked: " + "; ".join(problems))


def merge_problems(selector: list[str], sha: str, default: str) -> list[str]:
    fields = "number,state,isDraft,baseRefName,headRefName,headRefOid,mergeable,mergeStateStatus"
    rc, out = run(["gh", "pr", "view", *selector, "--json", fields], cwd=PROJECT, timeout=45)
    try:
        pr = json.loads(out) if rc == 0 else None
    except ValueError:
        pr = None
    if not isinstance(pr, dict):
        return ["could not read the pull request state (gh or network); not merging blind"]
    problems = []
    if pr.get("state") != "OPEN":
        problems.append(f"state is {pr.get('state')}")
    if pr.get("isDraft"):
        problems.append("it is a draft")
    if pr.get("baseRefName") != default:
        problems.append(f"base is {pr.get('baseRefName')}, not {default}")
    if pr.get("headRefOid") != sha:
        problems.append("the head moved since it was verified (--match-head-commit differs)")
    if pr.get("mergeable") != "MERGEABLE":
        problems.append(f"mergeable is {pr.get('mergeable')} (conflicts, or not computed yet)")
    if pr.get("mergeStateStatus") not in ("CLEAN", "HAS_HOOKS"):
        problems.append(f"merge state is {pr.get('mergeStateStatus')}")
    slug = origin_slug()
    if not slug:
        problems.append("cannot tell the GitHub repository from the origin remote")
    else:
        problems += ci_problems(slug, sha)
        rc, behind = run(["gh", "api", f"repos/{slug}/compare/{default}...{sha}", "--jq", ".behind_by"], cwd=PROJECT, timeout=45)
        if rc != 0 or not behind.isdigit():
            problems.append(f"could not verify the branch is up to date with {default}")
        elif int(behind) > 0:
            problems.append(f"branch is {behind} commit(s) behind {default}: merge origin/{default} into it, run the gates, push")
    return problems


def gh_api_list(path: str, key: str) -> list[dict] | None:
    """GET a GitHub API path and return the objects listed under key; None when unreadable."""
    rc, out = run(["gh", "api", path], cwd=PROJECT, timeout=45)
    try:
        data = json.loads(out) if rc == 0 else None
    except ValueError:
        return None
    items = data.get(key) if isinstance(data, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else None


def ci_problems(slug: str, sha: str) -> list[str]:
    """CI verdict for the PR head from the GitHub Actions API.

    Fine-grained tokens cannot read checks or commit statuses (the checks API and
    statusCheckRollup answer 403), but Actions: read covers workflow runs and jobs. The latest
    run of every workflow for the head commit must have succeeded, and so must the policy's
    required_check job (ci-ok). Keep in sync with .claude/skills/iace-loop/scripts/ci_state.py.
    """
    required, ok = POLICY["required_check"], ("success", "skipped", "neutral")
    runs = gh_api_list(f"repos/{slug}/actions/runs?head_sha={sha}&event=pull_request&per_page=100", "workflow_runs")
    if runs is None:
        return ["could not read the CI runs (gh or network; the token needs Actions: read)"]
    latest: dict[str, dict] = {}
    for r in runs:  # re-runs and reopened PRs leave older runs for the same commit behind
        key = r.get("path") or r.get("name") or "?"
        if key not in latest or (r["run_number"], r["run_attempt"]) > (latest[key]["run_number"], latest[key]["run_attempt"]):
            latest[key] = r
    if not latest:
        return [f"no CI run for the head commit {sha[:8]} yet"]
    problems, required_ok = [], False
    for _, r in sorted(latest.items()):
        name = r.get("name") or r.get("path")
        if r.get("status") != "completed":
            problems.append(f"workflow {name} is {r.get('status')}")
            continue
        if r.get("conclusion") not in ok:
            problems.append(f"workflow {name} concluded {r.get('conclusion')}")
        jobs = gh_api_list(f"repos/{slug}/actions/runs/{r['id']}/jobs?per_page=100", "jobs")
        if jobs is None:
            problems.append(f"could not read the jobs of workflow {name}")
            continue
        for j in jobs:
            if j.get("conclusion") not in ok:
                problems.append(f"job {j.get('name')} concluded {j.get('conclusion')}")
            elif j.get("name") == required and j.get("conclusion") == "success":
                required_ok = True
    if not required_ok:
        problems.append(f"required check '{required}' has not passed on the head commit")
    return problems


# --- other programs ---------------------------------------------------------------------------


def check_terraform(prog: str, args: list[str]) -> None:
    rest = [a for a in args if not a.startswith("-chdir")]
    sub = next((a for a in rest if not a.startswith("-")), "")
    dangerous = {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh"}
    if sub in dangerous or (sub == "state" and any(a in ("rm", "mv", "push", "replace-provider") for a in rest)):
        raise Blocked(f"{prog} {sub} changes real infrastructure; the loop never does that")


def check_rm(args: list[str], cwd: Path | None, env: dict[str, str]) -> None:
    recursive = any(a in ("-r", "-R", "--recursive") or re.match(r"^-[a-zA-Z]*[rR]", a) for a in args)
    if not recursive:
        return
    home = Path.home().resolve()
    for target in (a for a in args if not a.startswith("-")):
        if target in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "*", ".", "./", "..", "../", "../*"):
            raise Blocked(f"rm -r {target} is too broad; delete specific paths inside the repository")
        path = resolve(target, cwd, env)
        if path is None:
            continue
        if path in (Path("/"), home) or path == PROJECT or path in PROJECT.parents or path == PROJECT / ".git":
            raise Blocked(f"rm -r {target} would delete the project, its git data or a parent directory")


WRITE_ALL = {"rm", "rmdir", "chmod", "chown", "chgrp", "touch", "truncate", "tee", "mkdir", "shred", "unlink"}
WRITE_DEST = {"cp", "install", "ln", "rsync"}


def check_writes(prog: str, args: list[str], cwd: Path | None, env: dict[str, str]) -> None:
    targets = [a for a in args if not a.startswith("-")]
    if prog in WRITE_ALL or prog == "mv":
        paths = targets
    elif prog in WRITE_DEST:
        paths = targets[-1:]
    elif prog == "sed" and any(a == "-i" or a.startswith(("-i", "--in-place")) for a in args):
        paths = targets
    elif prog == "perl" and any(re.match(r"^-[a-zA-Z]*i", a) for a in args):
        paths = targets
    elif prog == "dd":
        paths = [a[3:] for a in args if a.startswith("of=")]
    else:
        return
    for p in paths:
        check_harness_path(p, cwd, env, prog)


def check(argv: list[str], prev_op: str, prev_prog: str, cwd: Path | None, env: dict[str, str]) -> None:
    argv = unwrap(argv)
    if not argv:
        return
    prog = os.path.basename(argv[0])
    args = argv[1:]
    if prog in SHELLS and "-c" in args:
        idx = args.index("-c") + 1
        evaluate(args[idx] if idx < len(args) else "", cwd, dict(env))
        return
    if prev_op in ("|", "|&") and prog in INTERPRETERS and prev_prog in ("curl", "wget"):
        raise Blocked("piping a download into an interpreter runs unreviewed code; download, inspect, then run")
    if prog == "git":
        check_git(args, cwd, env)
    elif prog == "gh":
        check_gh(args)
    elif prog in ("terraform", "tofu"):
        check_terraform(prog, args)
    elif prog == "rm":
        check_rm(args, cwd, env)
    check_writes(prog, args, cwd, env)


def evaluate(text: str, cwd: Path | None, env: dict[str, str]) -> None:
    prev_prog = ""
    for argv, prev_op, redirs in commands(text):
        if argv and all(ASSIGNMENT.match(w) for w in argv):  # VAR=value on its own: remember it
            for w in argv:
                key, value = w.split("=", 1)
                env[key] = expand(value, env)
            prev_prog = ""
            continue
        for target in redirs:
            check_harness_path(target, cwd, env, "redirect output to")
        core = unwrap(list(argv)) if argv else []
        if core and os.path.basename(core[0]) == "cd":
            target = core[1] if len(core) > 1 else str(Path.home())
            cwd = None if target == "-" else resolve(target, cwd, env)
        check(argv, prev_op, prev_prog, cwd, env)
        prev_prog = os.path.basename(core[0]) if core else ""


def check_file_tool(tool_input: dict) -> None:
    raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if raw:
        path = Path(raw) if os.path.isabs(raw) else PROJECT / raw
        if is_harness(path.resolve()):
            ASKS.append(f"edit {raw}")


def main() -> int:
    try:
        data = json.loads(sys.stdin.read())
        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            raise ValueError
    except (ValueError, AttributeError):
        print("BLOCKED by guard-loop.py: the hook input is not valid JSON", file=sys.stderr)
        return 2
    tool = data.get("tool_name") or "Bash"
    try:
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            check_file_tool(tool_input)
        elif tool_input.get("command"):
            evaluate(tool_input["command"], Path(data.get("cwd") or PROJECT), {})
    except Blocked as reason:
        print(f"BLOCKED by .claude/hooks/guard-loop.py: {reason}", file=sys.stderr)
        print("Do not work around this guard with other syntax; fix the cause or record a blocker.", file=sys.stderr)
        return 2
    if ASKS:
        reason = "Harness change needs a human: " + "; ".join(sorted(set(ASKS))[:5])
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a guard bug must not lock the session out
        print(f"guard-loop.py internal error (command allowed): {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
