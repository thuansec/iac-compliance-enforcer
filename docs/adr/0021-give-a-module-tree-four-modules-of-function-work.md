# 0021 · Give a module tree four modules' function work

- Status: accepted
- Date: 2026-10-09
- Task: T-0113c
- Amends: ADR 0009 (the tree's function work), ADR 0020

## Context
ADR 0009 gives a module tree one module's budget of each kind of work, function work included
(2^23). ADR 0020 then charged for-expression iterations to that same function work,
conservatively: the collection's size, and per iteration 64 plus the body's source bytes and
the sizes of the values the body refers to.

T-0113c measured three realistic trees (testdata/realistic):
- `templates`: 50 instances rendering cloud-init templates with `%{ for }` directives.
  1.1 M of function work.
- `nested-maps`: ten environments of thirty services, flattened and looked up by key.
  0.7 M of function work.
- `fanout`: 150 module instances, each building 100 security-group rules from nested for
  expressions and a dynamic block. One instance uses about 67,800 units of function work, of
  which about 51,600 are for-expression charges. The tree needs about 10.3 M, more than the
  tree's 8.4 M, so the tree was truncated at about 120 instances and some resources were not
  scanned.

## Decision
- A module tree's function work (maxTreeFunctionWork) is four modules' worth, 2^25. Each
  module's own function work (maxFunctionWork, 2^23) is unchanged, so no single module can do
  more than before.
- testdata/realistic is kept as a regression test (TestRealisticTreesStayUnderTheWorkLimit).
  Each tree must evaluate:
  - with no limit diagnostic and no unknown resource value;
  - with its expected number of module instances and resources;
  - using at most half the tree's function work, and each instance at most half a module's.

## Alternatives considered
- Lower the for-expression charges. They are conservative on purpose (ADR 0020): the
  reference and iterator charges are what keep a large value from being copied on every
  iteration, and the iteration weight bounds time. Weight 0 alone did not bring `fanout`
  under the old budget.
- Raise the per-module budget: it would also raise what a single module can make iace do.

## Consequences
- Positive: fan-outs with nested for expressions are evaluated in full up to about 179 instances
  of the `fanout` shape (124 before), where the tree's expansion work now binds (T-0113d).
  At 150 instances, `fanout` uses 31% of the new budget.
- Negative / accepted risks: a tree's worst case for function work is four times higher. It
  bounds CPU time (function work is transient: arguments and results), from about 1 s to a few
  seconds, not live memory, which the value budgets still bound.
- Follow-ups:
  - At 200 instances, `fanout` reaches the tree's expansion work (ADR 0009/0010: about 11,700
    bytes of re-evaluated source per instance against 2^21). This is separate from function
    work (T-0113d).
  - Not fixed here: a for body that passes a whole large map to a function on every iteration
    (`{ for k in keys(local.m) : k => lookup(local.m, k, null).x }`) reaches one module's
    function work, which this ADR leaves unchanged, from about 140 entries. Each call measures
    its whole map argument (bounded functions), and ADR 0020 charges the reference again
    (T-0113e).
