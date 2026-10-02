# 0001 · Record architecture decisions

- Status: accepted
- Date: 2026-10-02
- Task: T-0005

## Context
iace is built mostly by an automated loop that starts every iteration with a fresh context, so
the reasons behind a design must live in the repository rather than in anyone's memory. Owner
decisions (license, AI provider, key custody, repository visibility) are already logged as D-xx
entries in `docs/plan/BACKLOG.md` and `docs/plan/PROGRESS.md`. Design choices made while
building need a durable home too: choosing between real alternatives, changing a contract,
adding a significant dependency, or accepting a security trade-off.

## Decision
Record each such choice as an architecture decision record in `docs/adr/NNNN-kebab-title.md`,
following the template in the iace-architecture skill (Context, Decision, Alternatives
considered, Consequences) and keeping it under a page. Numbers are sequential and never reused.
Accepted ADRs are immutable: a change of mind is a new ADR that supersedes the old one, whose
status then says so. A contract change (input document, findings, config, CLI and exit codes)
lands in the same commit as its ADR.

## Alternatives considered
- Decisions only in commit messages and pull requests: hard to find, and squash merges flatten them.
- One design document edited in place: it loses the history of why something changed.

## Consequences
- Positive: any iteration or reviewer can find why the code is shaped the way it is.
- Negative / accepted risks: a little ceremony for each significant decision.
- Follow-ups: ADR 0004 records the input document contract (T-0101); T-0802 records the
  policy-bundle signing design.
