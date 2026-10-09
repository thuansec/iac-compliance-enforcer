# 0018 · Bound postfix chains in evaluated expressions

- Status: accepted
- Date: 2026-10-09
- Task: T-0111c

## Context
An index or attribute chain (`x[k][k]...`, `x.a.b...`) closes every bracket it opens, so the
nesting guard (maxNesting open levels) does not see it. hclsyntax builds one nested node per step,
and walking such an expression (Variables, the function-call inspection) or evaluating it recurses
once per step. The T-0104a review measured about 2.4 GB for a 5 MiB chain. At the 1 MiB file limit
(ADR 0016), a chain has up to about 350,000 steps. The size estimates of locals and attributes
already refuse expressions over 256 KB of source before evaluation, but inspecting such an
expression still allocated about 600 MB and recursed about 350,000 frames deep (about 128 MB
of stack).

## Decision
- An expression about to be evaluated (scanTokens with maxOps, the same check that caps binary
  operators) may nest at most 1,024 postfix steps (maxChain, checkChains).
  - An index or attribute step right after a value (a name, a number, a splat `*`, or a closing
    bracket, parenthesis or quote) continues the chain.
  - The count adds up through nesting, as the syntax tree's depth does. A bracket's content starts
    at the count where the bracket opens, and the deepest count inside it carries out when it
    closes. So a chain wrapped in parentheses, continued in an index key or a call argument, or
    split by `.*` still counts as one.
  - Any other token ends the chain at its level, so independent chains joined by an operator or
    listed as arguments count apart.
  - The count is conservative: a key's own steps count inside its index step, so `x[local.k]`
    counts two per step. Real configurations stay far below the bound either way.
- A longer chain makes the expression too complex: it is unknown, with an expression_too_complex
  warning (which T-0109 maps to a limit_exceeded gap), before it is walked or evaluated.
- Parsing is not limited: the file parses, and only the expression is unknown.

## Alternatives considered
- Refuse such files at parse time (the nesting guard): a whole module would go unchecked for one
  expression.
- Rely on the size estimates alone: they run after the walk that recurses, and expressions under
  256 KB can still hold about 85,000 steps.

## Consequences
- Positive: no expression inspection or evaluation recurses through more than 1,024 nested
  postfix steps. The refused 1 MiB chain now uses no measurable stack (128 MB before).
- Negative: the bound limits recursion, not memory. Refusing the 1 MiB chain still allocates
  about 1.1 GB in total (transient garbage), because its source is lexed once per check
  (inspectExpr, then safeToEvaluate in evalExpr). T-0111e lexes an expression once per
  evaluation.
- Accepted risks: none for real configurations, which chain a handful of steps.
