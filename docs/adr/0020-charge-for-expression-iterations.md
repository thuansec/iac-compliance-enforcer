# 0020 · Charge for-expression iterations to the module's function work

- Status: accepted
- Date: 2026-10-09
- Amended by: ADR 0021 (the tree's function work is four modules' worth), ADR 0023 (references
  passed to lookup)
- Tasks: T-0113; T-0113a (the iteration weight and directive strings, listed below as a follow-up)

## Context
hcl evaluates for expressions internally. Nested ones multiply: three over a 200-element list
build 8 million elements in 3 s, and over 1,000 elements about a billion (T-0104c review). The
instances of a resource repeat them: a for expression in a block with count = 10,000 runs
10,000 times (T-0106b review). iace cannot count inside hcl's loop. hcl does evaluate a for
expression's collection once per evaluation of the for expression, through an ordinary
expression node that iace can replace.

## Decision
- Every for expression in a syntax tree iace evaluates is rewritten once, after parsing
  (rewriteForExprs), to iterate over
  `__iace_for(collection, bodyBytes, iteratorUses, __iace_refs(whole...), __iace_elems(indexed...))`.
  - This covers module files, tfvars files, `--var` expressions and templatefile templates
    (`%{ for }` directives parse to the same node).
  - bodyBytes is the source size of the key, value and condition expressions.
  - The reference lists are the body's references outside its own iterators and outside nested
    for expressions, which charge themselves. A reference the body only indexes (`local.m[k]`)
    is in the indexed list.
- `__iace_for` (forFunction) returns the collection unchanged after charging, before the loop
  runs, what its iterations can build. It charges the module's function work (maxFunctionWork),
  which the tree's function work also bounds.
  - It takes the collection as an expression closure and evaluates it itself, so cty never
    walks the value outside the budget. Errors from evaluating the collection are returned by
    evalExpr, or by templatefile for a template's directives, as hcl would have returned them.
  - It measures the collection only up to the work left, and charges the measured size on every
    evaluation. An inner loop over a small collection holding a large value pays for it each
    time.
  - Each iteration costs forIterationWork (64) plus bodyBytes, plus the size of every value the
    body refers to (`__iace_refs`), plus the largest element of every value it only indexes
    (`__iace_elems`). So a body that builds a large value on every iteration
    (`"${local.big}${i}"`) is refused before it builds it.
  - The collection's size is charged once for each use of the iterators.
  - forIterationWork bounds time. hcl allocates about 1.3 KB per iteration (scopes and
    conversions), all short-lived: the live heap of the cases below stays at a few MB.
    - At 64, the work allows about 125,000 small-body iterations per module tree (ADR 0009 gives
      the whole tree one module's function work).
    - Three nested `%{ for }` directives over 1,000 elements stop after 0.3 s and 220 MB of
      total allocation (1.3 s under -race); at 16 they took 0.7 s and 583 MB (3.2 s under -race)
      (T-0113a).
  - A `%{ for }` directive's body is also wrapped in `__iace_val`, which charges the string each
    iteration produces, up to the work left. Deep nesting over one element, whose iterations
    cost almost nothing, cannot copy a large string at every level: 300 levels around 200 KB
    allocated 290 MB and evaluated in full; they are now limited.
  - `__iace_refs` and `__iace_elems` evaluate their arguments as expression closures, so a
    reference that cannot be evaluated counts nothing and adds no error. hcl reports it if the
    body evaluates it.
  - Every measurement stops at the work left and is charged. With no work left, nothing is
    walked: the references count as the whole limit, so the loop is refused at once.
  - Over the limit, `__iace_for` returns an unknown value that keeps the collection's top-level
    marks (a deeper walk would be free work). The for expression is then unknown, and evalExpr reports `expression_too_complex`
    ("For expression too large"), which T-0109 maps to a limit_exceeded gap.
  - Nested loops charge every inner evaluation, and resource instances charge every evaluation,
    so one module's work bounds them all together.
- evalExpr puts the internal functions in scope through a child context, and only for an
  expression that holds a rewritten for expression. Other expressions keep their callers'
  contexts, and hcl's own errors (for example "Function calls not allowed" in a variable
  default).
- Variable type constraints: typeexpr evaluates `optional()` defaults itself, outside the
  rewrite. So a type constraint with a for expression is refused before typeexpr reads it, in
  HCL and JSON. The type is unknown, with an `expression_too_complex` warning.
- `.tf.json`: hcl parses a JSON template string only while it evaluates the value, so iace
  cannot rewrite it in place.
  - A value that is a single template string is parsed and evaluated by iace instead
    (jsonStringTemplate), as hcl's JSON decoder would, with its for expressions rewritten.
    Without a context, JSON strings stay literal, as hcl keeps them.
  - A for expression in a template string nested in a JSON object or array is refused: the
    value is unknown with `expression_too_complex` (inspectExpr).

## Alternatives considered
- A wall-clock timeout: it cannot stop hcl's loop or free its memory, and results would depend
  on machine speed.
- Rejecting nested for expressions: real configurations nest them over small collections.
- An evaluator of iace's own for hcl expressions: large, and it would drift from hcl.

## Consequences
- Positive: a scan cannot hang or exhaust memory through for expressions. About a billion
  nested iterations now stop at the limit in a few seconds. A loop that builds a 200 KB string
  per element allocated 393 MB, and 1.36 GB as a `%{ for }` directive; both now stay under
  100 MB.
- Negative / accepted risks:
  - A configuration that calls the internal functions itself gets their charging behaviour.
    Their numeric arguments are clamped, so they can neither refund nor overflow the work.
  - The estimate is conservative. A body that copies a whole referenced value on every
    iteration is charged that value's size each time, so a large configuration can reach the
    limit sooner than its real work would.
  - An HCL expression that holds a for expression and is evaluated without a context (a
    variable default, `--var`) has the internal functions in scope. A function call there is
    still rejected, but hcl reports "Call to unknown function" instead of "Function calls not
    allowed".
  - The iteration weight (64) reaches the limit about four times sooner than 16. For example,
    5,000 resource instances each running a 20-element for expression now reach it. Whether real
    configurations stay under it is to be measured (T-0113c).
  - For-expression work shares the budget with function calls, so trees with heavy for_each
    use may reach module_work_limit gaps sooner.
  - Nested for expressions that build collections are charged by their own iterations and
    references, not by the size of the results they hand to the loop around them. Template
    directives are charged their strings (T-0113a).
  - A for expression in a nested JSON template string is unknown even when it is small
    (T-0113b).
