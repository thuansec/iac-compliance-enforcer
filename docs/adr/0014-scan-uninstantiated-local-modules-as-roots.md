# 0014 · Scan uninstantiated local modules as roots

- Status: accepted
- Date: 2026-10-09
- Task: T-0107e
- Extends: ADR 0008

## Context
ClassifyModules treats every directory called through a local source as a child, and children
are scanned only through the roots that call them. A pull request can keep a module out of
every scan with a call that never instantiates it: `count = 0`, an empty `for_each`, or a source
that only an override file sets (ADR 0005 does not merge override files, but Terraform would
load that module). The module's resources would then be checked nowhere, silently.

## Decision
- EvaluateRoots evaluates every root's tree, then finds the local children that no tree has an
  instance of. The children are those ClassifyModules found in discovered directories, plus
  every directory a loaded tree reaches through a resolved call, even one with `count = 0`.
  Calls made inside hidden modules are seen only that way. A child is covered when any tree has
  an instance of it, even one skipped for the tree's budget, because that instance is reported
  at its call (ADR 0009).
- Each uncovered child is scanned as a root, an orphan:
  - It gets a warning, uninstantiated_module, on its root instance.
  - It is evaluated with its own defaults and tfvars only. The pipeline's `--var` and
    `--var-file` values belong to the real roots.
  - Variables without a default are unknown.
- Orphans are promoted in rounds. An orphan that another orphan calls waits, because evaluating
  its caller may instantiate it. When every orphan waits, the first by path that is in a cycle
  of orphans goes first. So each orphan is scanned once, through the highest uncovered caller.
- Orphans never trust the module manifest (ADR 0013): the pipeline prepared `.terraform` for
  its roots only, so an orphan's remote calls stay unresolved and are reported.
- A hidden child scanned as a root is listed like any hidden module directory, within
  discovery's file budget.

## Alternatives considered
- Report uninstantiated children only as a coverage gap: safe, but it leaves code that
  Terraform may deploy (override redirects) or that a later change instantiates unchecked.
- Treat `count = 0` children as instantiated: a trivial way to hide a module from every scan.

## Consequences
- Positive: every local module directory is either evaluated in some tree or scanned on its own.
  The warning tells users why the values are unknown.
- Negative / accepted risks: code that is genuinely disabled (`count = 0`) is still checked and
  may produce findings, which the exception mechanism (M4) or a fix resolves. Orphans evaluated
  without the pipeline's variables can show more unknown values than a real instance would.
