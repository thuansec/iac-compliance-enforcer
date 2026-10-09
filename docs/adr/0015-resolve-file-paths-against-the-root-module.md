# 0015 · Resolve file paths against the root module, within the scan root

- Status: accepted
- Date: 2026-10-09
- Task: T-0107f

## Context
T-0105c resolved `file`, `fileexists` and `templatefile` against each module's own directory,
with `path.module = "."`, and confined reads to that directory through a sub-root. That is right
for a root module evaluated on its own, but not inside a module tree. Terraform resolves
relative paths against its working directory, the root module, for every module. Inside a child,
`path.module` is the child's path from there, such as `modules/net` or `../../modules/net` for a
root in `envs/prod`, and `path.root` is `.`. A child's `file("${path.module}/policy.json")`
therefore has to leave the root module's directory to reach the child's file, so a
per-directory confinement would make every such call unknown.

## Decision
- Every module instance has a base directory, the root module's directory, and a path.module.
  For a root module these are its own directory and `.`. For a child instance, EvaluateTree sets
  the tree's root directory and the child's slash-separated path from it. `path.root` is `.`,
  and `path.cwd` stays unknown.
- The file functions join a relative path to the base directory. The confinement boundary is
  the scan root, as for every other scanned-content read (`internal/fsutil` on `os.Root`):
  - absolute, home-relative and drive-letter paths are refused (file_outside_module);
  - a joined path that leaves the scan root is refused (file_outside_module);
  - a symlink that leaves the scan root is refused by os.Root (file_unreadable).
- This replaces T-0105c's per-module confinement for root modules too. A root module may now read
  files elsewhere in the scanned repository, as Terraform would.

## Alternatives considered
- Keep per-module confinement and rewrite `${path.module}` to the module directory: wrong for
  bare relative paths, which Terraform resolves against the root module, and different from the
  path.module that policies see.
- Confine to the root module's directory: still breaks every child outside it (`../modules`),
  the most common layout.

## Consequences
- Positive: the file functions and path.* behave as in Terraform, through any module layout.
- Negative / accepted risks: a module can read any file of the scanned repository, still
  capped per file and charged as function work (T-0105c). The repository is the scan's input,
  so this exposes nothing beyond it, and nothing outside the scan root is ever read.
