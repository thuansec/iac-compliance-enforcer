# 0041 · Charge optional() defaults, and read only static ones

- Status: accepted
- Date: 2026-10-13
- Task: T-0116k
- Extends: ADR 0029, ADR 0040

## Context
hcl's typeexpr reads a variable's type constraint itself. For each `optional(T, default)` it
evaluates the default without a context and converts it to T, so none of iace's charges apply.
A `set(set(string))` default of 100 sets of 200 strings took 6.3 s to declare, and one use of it
18 s more (T-0116i review). Two more problems turned up:
- iace rewrites the conditionals and comparisons in a module's native expressions into its own
  charging functions. Those rewritten defaults fail when typeexpr evaluates them without
  functions, so typeexpr dropped the defaults without a word. This was the case on main too.
- A `.tf.json` type is a string that hcl parses at read time. It is not one of the module's
  sources, so iace's evaluator (evalExpr) cannot evaluate, and so cannot charge, a default
  inside it.

## Decision
- Before typeexpr runs, chargeOptionalDefaults walks the type expression as typeexpr does
  (hcl.ExprCall, ExprMap, ExprList), so it covers `.tf.json` types too. For each optional()
  default it charges two things:
  - evaluating the default twice (once to measure it, once for typeexpr), at its size each time;
  - converting it to its attribute's type (conversionCostDone). Sets of sets pay setBuildCost's
    weight squared (ADR 0040), and unification is charged as in ADR 0029.
- Only static literal defaults are read: literals, negation, `!`, parentheses, tuples, objects
  with literal or bare-word keys, and templates without interpolation. Evaluating these is linear
  and needs no charge beyond their size.
- A default that is not static, or that does not fit, makes the variable's type unknown with an
  expression_too_complex warning, "Optional defaults not read". This is the same outcome as a
  type expression containing `for`. The variable's value is then taken as given. A refusal
  spends the work its estimate did.

## Consequences
- An optional() default with a conditional, comparison or other operator, apart from `-` and
  `!`, now makes the type unknown with a warning. Before, native ones silently lost their
  defaults, and `.tf.json` ones were read uncharged. Terraform requires defaults to be static
  values without references or functions, so such defaults are rare.
- Defaults applied inside the elements of a set still rebuild the set uncharged (T-0116l).
