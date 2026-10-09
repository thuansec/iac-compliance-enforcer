# 0022 · Give a module tree four modules' expansion work

- Status: accepted
- Date: 2026-10-09
- Task: T-0113d
- Amends: ADR 0009 (the tree's expansion work)

## Context
ADR 0009 gives a module tree one module's budget of each kind of work, including expansion work:
the source re-evaluated for repeated instances (count, for_each, dynamic blocks), 2^21 bytes.

T-0113c found that the realistic fan-out (testdata/realistic/fanout) reached it. Each of its
module instances re-evaluates about 11,700 bytes (a dynamic block of 100 security-group rules),
so the tree stopped at about 179 instances, and 200 left 42 of 400 resources unscanned.

At 200 instances, the whole scan took about 1.0 s for 2,336,400 bytes of expansion work: at most
about 431 ns per byte, within ADR 0009's measured 200 to 630 ns per byte.

## Decision
- A module tree's expansion work (maxTreeExpansionWork) is four modules' worth, 2^23 bytes. Each
  module's own expansion work (maxExpansionWork, 2^21) is unchanged.
- The realistic fan-out is tested at 200 instances. TestRealisticTreesStayUnderTheWorkLimit also
  requires each tree to use at most half the tree's expansion work: fanout uses 28%.

## Alternatives considered
- Charge dynamic-block content more precisely: the charge already counts the content's source
  once per entry, which is what evaluating it costs. A smaller charge would under-count.
- Raise the per-module budget: it would also raise what a single module can make iace do.

## Consequences
- Positive: the realistic fan-out of 200 instances is evaluated in full.
- Negative / accepted risks: a tree's worst case for expansion work is four times higher. The
  tree is checked before an instance and charged after it, and an instance can add its own
  expansion and its call arguments' expansion (2 × 2^21), so the worst case is about 12.6 MB.
  That is CPU time: about 5 s at the measured 420 ns per byte, and up to 8 s at ADR 0009's 630
  ns per byte (a probe of 1,000 calls of a 300-operator body under count = 10,000 took 4.1 s,
  1.6 s with the old budget), comparable with the tree's 8 MiB source budget.
  TestEvaluateTreeBoundsTheWholeTree bounds it. The values the expansions produce stay bounded by the unchanged value, structure and
  instance budgets.
