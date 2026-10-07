# 0005 · Report override files instead of merging them

- Status: accepted
- Date: 2026-10-07
- Task: T-0103

## Context
Terraform merges `override.tf`, `*_override.tf` and their `.tf.json` forms into the blocks they
name, attribute by attribute, with special rules for nested blocks, `locals`, `terraform` and
`required_providers`. An override can change a security-relevant value: `main_override.tf`
can set `acl = "public-read"` on a bucket whose `main.tf` is private. Merging correctly needs
the static evaluator and module structure, which arrive later in M1. Until then, iace can
either ignore override files, report them, or merge them approximately.

## Decision
Until override merging is implemented, ParseModule reports every override file as a warning
diagnostic `override_not_merged`. It also checks the file for syntax errors and nesting, as
Terraform would reject it, but does not use its blocks. T-0109 turns that diagnostic into a
coverage gap naming the file, so the report states that the file's settings were not checked.
`--fail-on-gaps` makes such a scan exit 2.

## Alternatives considered
- Ignore override files: an attacker-controlled fail-open path that leaves no trace.
- Approximate merging (overwrite top-level attributes only): it looks complete but gets nested
  blocks and special blocks wrong. A silent wrong answer is worse than a visible gap.
- Fail the scan (exit 2) whenever an override file exists: too strict for repositories that use
  overrides legitimately, and the gap already makes the risk visible and enforceable.

## Consequences
- Positive: no silent pass; the decision point (`--fail-on-gaps`) stays with the pipeline owner.
- Negative / accepted risks: without `--fail-on-gaps`, a pull request can weaken a setting
  through an override file and pass with a reported gap.
- Follow-ups: T-0109 (gap mapping); T-0112 (merge override files with Terraform semantics); threat
  model entry T14.
