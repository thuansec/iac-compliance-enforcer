# 0017 · Bound the syntax trees a scan keeps

- Status: accepted
- Date: 2026-10-09
- Task: T-0111b
- Extends: ADR 0016

## Context
ADR 0016 bounds one file: at 1 MiB, its kept syntax tree is at most about 170 MB, and parsing it
peaks at about 450 MB. A scan keeps the trees of every file of every module of every root,
because evaluation reads module bodies after parsing, and EvaluateRoots keeps each root's tree
in its result. A directory is parsed once per tree, so a module used by many roots is kept once
per root. Ten thousand files (the discovery limit) of a few hundred kilobytes each would keep
many gigabytes.

## Decision
- A scan has one ParseBudget in budget tokens, which Limits carries as a pointer so every
  ParseModule call of the scan shares it. EvaluateRoots, the scan's entry point, creates one
  when Limits has none, and DefaultLimits creates a fresh one. Its default is MaxScanTokens,
  3,000,000.
- A file's cost (lexCost):
  - HCL: its lexer tokens, from the lex the nesting guard already does, plus one per 30 source
    bytes, because a kept file holds its source, and its long literals hold a copy, whatever its
    token count. Without the byte term, a 1 MiB string literal cost 18 tokens and kept about
    2 MB.
  - JSON: its bytes.
- TestKeptHeapPerBudgetToken measures what a parsed module keeps per budget token, at most 140
  bytes:

  | shape | bytes per budget token |
  |---|---|
  | operator chain | 128 |
  | list | 82 |
  | call arguments | 82 |
  | realistic resources | 74 |
  | long literal | 60 |
  | long comment | 30 |

  So the budget keeps at most about 384 MB. With one file's transient parse peak (about 450 MB,
  ADR 0016), that leaves room for evaluation within the 1 GiB scan budget.
- A file is parsed, and its source kept, only when its cost fits what is left. Otherwise it is
  not parsed, keeps nothing, and a parse_limit warning names it. T-0109 maps that to a
  limit_exceeded gap, so `--fail-on-gaps` fails the scan. A cost is charged whether or not the
  file then parses cleanly.
- A nil budget passed directly to ParseModule takes everything. That is only for callers, such
  as unit tests, that bound memory otherwise.

## Alternatives considered
- Release syntax trees after evaluation: evaluation of a tree needs all of its modules' bodies at
  once, and results keep resources that point into them; it would need a copying pass first.
- Count only bytes for HCL: a byte cap overcharges realistic files, which have about 270,000
  tokens per MiB, by a factor of four. Count only tokens: long literals and comments keep their
  bytes at a few tokens each (the T-0111b review: 230,000 such files would fit the budget).
- Parse each directory once per scan, not once per tree: the trees' evaluation state is
  per-instance already (NewInstance), so parses could be shared later. That would lower the
  cost, not remove the need for a bound.

## Consequences
- Positive: what a scan keeps of its sources is bounded by configuration, not by the repository.
  Realistic repositories stay far below the budget: about 380,000 budget tokens per MiB of
  realistic HCL, and 5,000 resources are well under a MiB.
- Negative / accepted risks: very large repositories, or many roots sharing large modules, have
  files left unparsed past the budget, visibly. A pipeline can raise the budget for its own
  memory (a CLI option in a later task).
