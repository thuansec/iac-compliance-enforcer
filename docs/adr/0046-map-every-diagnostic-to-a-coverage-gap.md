# 0046 · Map every diagnostic, skip and limit to a coverage gap

- Status: accepted
- Date: 2026-10-17
- Task: T-0109d
- Amends: ADR 0004

## Context
The input document's coverage gaps are how a user sees what iace did not check. The loader
records what it could not do in several places: discovery skips (Discovery.Skipped), module-tree
skips and truncation (ModuleTree.Skipped, Truncated), parse diagnostics on each tree node,
evaluation diagnostics on each module instance (39 diagnostic codes today), and what
normalization could not express (ADR 0045: resources whose values are not paths, incomplete
references). ADR 0004 defined five gap kinds, which do not cover a skipped symlink, incomplete
references, or the many warnings that mean "this part was only partly analyzed". A diagnostic
that maps to no kind would be dropped, which is a silent pass.

## Decision
1. Three gap kinds are added to v1 (an additive enum change, in the schema, the model and the
   reference): `skipped_file` (a symlink that leaves the scan root, a symlinked directory, a file
   that is not regular), `incomplete_references` (a resource or output whose references may be
   missing), and `incomplete_analysis` (anything else iace could not fully analyze; the detail
   names the diagnostic code or what could not be expressed).
2. Every diagnostic becomes a gap. Error severity is always `parse_error` (the scan exits 2).
   Otherwise an explicit table (`diagGapKinds`) maps each code: `module_unresolved` →
   `unresolved_module`; `unsupported_function` → `unsupported_function`; `unknown_expansion`,
   `invalid_expansion` → `unknown_expansion`; the limit codes (`expression_too_complex`,
   `value_too_large`, `function_limit`, `expansion_limit`, `module_work_limit`, `file_limit`,
   `parse_limit`, `nesting_too_deep`, `too_many_diagnostics`) → `limit_exceeded`;
   `references_incomplete` → `incomplete_references`; every other code → `incomplete_analysis`.
   A code missing from the table also becomes `incomplete_analysis`, and a test that reads every
   `DiagCode` constant from the package source fails when one is missing.
3. Skips: `too_large` and `file_limit` → `limit_exceeded`; `symlink_escape`,
   `symlinked_directory` and `not_regular` → `skipped_file`. A truncated module tree →
   `limit_exceeded`. A discovery skip belongs to every root whose module tree loads the skipped
   path's directory (each of them misses the file); when no tree loads it, to the root whose
   directory most deeply contains it, else to the first document. When every Terraform file was
   skipped and no root remains, one document for the scan root carries the skips.
4. Settings iace reads but does not evaluate are unknown, never absent: provider blocks list
   every attribute and nested block they set (override-merged and dynamic blocks included) as
   null and in `unknown` until provider arguments are evaluated (T-0122), and a backend keeps
   only literal values (T-0109c). Absent would tell a policy the setting is not there.
5. A gap's detail is iace-authored text (code, summary, diagnostic detail, path); it never
   quotes source values. The only source text it names is a block label, quoted, such as the
   module call an `unresolved_module` gap names. Gaps are deduplicated and sorted by file, line,
   kind and detail.

## Alternatives considered
- One generic kind for everything not in ADR 0004: policies and reporters could not tell a
  skipped file from an unresolved reference, and gating by kind would be all or nothing.
- Dropping warnings that look harmless (duplicate declarations, uninstantiated modules): each
  means part of the configuration was read differently than Terraform would, so hiding it is a
  silent pass.
- Reporting a discovery skip in every document: roots that never load the file would report it.
- Owning skips by directory prefix only: a module shared by several roots lies outside them, so
  its skipped file was reported in an unrelated root and missing from the roots that load it.

## Consequences
- Positive: nothing the loader gave up on can be silently dropped; a new diagnostic code fails a
  test until it is mapped.
- Negative / accepted risks: documents carry more gaps (every warning), which reporters must
  group; a skip in a directory no tree loads is attached to the containing or first root.
- Follow-ups: the harness reference lists the new kinds (T-0110b); `iace inspect` and `iace scan`
  exit 2 on a `parse_error` gap (T-0109e, T-0206).
