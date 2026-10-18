# 0050 · Name root modules by path when scanning several paths

- Status: accepted
- Date: 2026-10-18
- Task: T-0206c
- Amends: the finding v1 `root_module` and `fingerprint` definitions (findings-and-cli.md)

## Context
`root_module` is a root module's directory relative to the scan root, and the fingerprint
hashes it (ADR 0049). `iace scan PATH...` has no single scan root: two paths that each hold a
root module "." would give two findings the same root module, file and fingerprint. Naming roots
by the path as typed would carry absolute host paths or `..` into reports and fingerprints,
which then change with the runner's checkout directory and leak its layout. Nested paths would
scan the inner root twice.

Options:
- (a) Qualify by each path relative to the working directory, and refuse paths outside it and
  nested paths.
- (b) Use the paths' common ancestor as one scan root. Names would change when a path is added
  or removed, and the ancestor can be "/".
- (c) Prefix an index (`1:`, `2:`). Names would depend on argument order.

## Decision
Option (a). With one path, nothing changes: that path is the scan root. With several, each is
made relative to the working directory and every root module, finding file, coverage-gap file
and input is prefixed with it (`infra/prod` + `.` is `infra/prod`); the fingerprint uses the
qualified root module. A path outside the working directory, or one inside another scan path, is
a usage error (exit 2). Paths are scanned in sorted order, so argument order never changes the
report.

## Consequences
- Fingerprints are stable across checkouts and runners, and reports carry no host paths.
- A finding's fingerprint differs between `iace scan infra/prod` (root ".") and
  `iace scan infra/prod infra/staging` (root "infra/prod"). Accepted: a pipeline uses one
  invocation consistently, and exceptions should be written for the invocation CI runs.
- `--var-file` is resolved inside every path.
- The findings reference in the harness needs the multi-path naming rule; it joins T-0110b.
