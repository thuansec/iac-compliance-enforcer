# 0008 · Bound the module call tree and never follow symlinked module directories

- Status: accepted
- Date: 2026-10-09
- Task: T-0107a

## Context
A root module's local module calls form a tree that iace loads from untrusted files. Terraform
sets no depth limit, and a module may call the same directory more than once, so two calls per
level reach 2^n modules at depth n. Each module is later evaluated (T-0107b), so the size of the
tree multiplies every per-module budget. The tree's entries cost memory too: unresolved calls
are kept so they can be reported, and a 5 MiB file holds hundreds of thousands of module blocks
(the T-0107a review built 20 million entries and 13.8 GiB from 1,000 calls to a 370 KB module).

Cycles are detected and directories parsed once by path. A symlinked directory inside the scan
root gives one directory many paths (`a/self -> .` yields `a/self/self/...`), which defeats both.

## Decision
- Nesting deeper than 32 levels (`MaxModuleDepth`) leaves the call unresolved (`depth_limit`).
- A tree holds at most 1,000 module calls (`MaxModuleCalls`), resolved or not. The first call
  past the limit is recorded as unresolved (`call_limit`) with one warning, the walk stops, and
  `ModuleTree.Truncated` is set; T-0109 turns it into a coverage gap.
- Each directory is parsed and its module blocks analyzed once (names, literal sources, where a
  local source leads, and their diagnostics); only cycle, depth and the limit are per call.
- A local source that passes through a symlink is unresolved (`symlinked_directory`), as
  discovery never follows symlinked directories. Each path component is checked with Lstat
  through the scan root.
- Hidden directories that discovery did not walk are listed within discovery's MaxFiles budget.

## Alternatives considered
- Bound only resolved calls: unresolved entries still grow as calls × blocks (the review's
  blocker).
- Resolve symlinks to a canonical identity: os.Root offers no realpath, and following links
  would make the loader disagree with discovery about which directories exist.
- No call limit beyond the depth limit: exponential fan-out within 32 levels.

## Consequences
- Positive: loading a tree costs at most 1,001 calls and one parse per directory; every place
  iace stops is a warning and, through T-0109, a gap.
- Negative / accepted risks: very large monorepo trees (over 1,000 calls) and repositories that
  reach modules through symlinks are partly unchecked, visibly, and fail with `--fail-on-gaps`.
- Follow-ups: T-0107b bounds the evaluation work of the whole tree; T-0109 maps
  module_unresolved and Truncated to gaps.
