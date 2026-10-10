# 0028 · Charge the unification of large tuple results in conditionals

- Status: accepted
- Date: 2026-10-10
- Task: T-0114c
- Extends: ADR 0020 (internal functions in rewritten syntax trees), ADR 0027
- Extended by: ADR 0029 (conversions into collection types; large objects)

## Context
When a conditional's two results have different types, hcl unifies them with cty. Unifying a
tuple type with another type makes a list, and cty sorts the tuple's element types with a
comparison that is quadratic in the tuple's length. One local `false ? var.c.t : ["x"]` over a
tuple took 0.16 s at 5,000 elements, 0.6 s at 10,000, 2.5 s at 20,000 and 11 s at 40,000
(profiled in convert.sortTypes and compareTypes). An untyped list in a variable default or a
local is a tuple, so a large one is easy to write.

A first approach evaluated each result itself and converted long tuples to lists ahead of hcl
(T-0114c review). It broke hcl's semantics:
- every result's diagnostics were reported, where hcl reports only the taken result's, and none
  when the condition is unknown. Terraform's guard idioms (`var.x == null ? "none" :
  var.x.name`) turned unknown, and `try` no longer caught a failing result;
- tuples were converted where hcl does not unify (against null, a dynamic value or the same
  type), turning numbers into strings.

## Decision
- Every conditional in a syntax tree iace evaluates is rewritten, with the other rewrites of ADR
  0020, so each result is `__iace_cond_branch(result)`.
- `__iace_cond_branch` takes the result as an ordinary argument: hcl evaluates it and applies its
  own rules for diagnostics, marks and unknowns. It returns the result unchanged, after charging
  the module's function work for unifying the result's type (unifyCost).
  - The type decides the cost, whatever the value: a null or unknown value of a large tuple type
    unifies the same way.
  - cty unifies recursively, so the walk goes through tuple element types, object attribute
    types and collection element types.
  - Each tuple type longer than 1,024 elements (largeTuple) costs length × length/16 (unifying
    costs about 6 ns per length² unit, against about 100 ns per unit of function work). When
    there is one, the number of types walked is added. Other types unify in linear time and cost
    nothing.
- Over the limit, the result is a dynamic unknown with its marks, so hcl does not unify a tuple
  type. evalExpr reports expression_too_complex ("Conditional too large": the result was not
  unified and may be unknown; when it is the result not taken, the value is still known).
- The charge is made whether or not hcl then unifies, which can only over-charge.
- The internal functions are in scope for every expression that holds a rewritten conditional,
  even one evaluated without a function table (a variable default).
- The wrapper's argument is walked by cty, so a conditional counts as walking its inputs (ADR
  0026, ADR 0027).

## Consequences
- Positive:
  - A conditional over a 40,000-element tuple stops at the limit in about 70 ms instead of
    unifying for 11 s.
  - Values, types and diagnostics are hcl's (TestConditionalsMatchHCL compares them for the
    guard idioms, try, unknown conditions, null and identical-type results, and template
    directives).
- Negative / accepted risks:
  - A tuple of about 11,000 elements or more in a conditional is unknown even where hcl would not
    have unified it (against null, a dynamic value or the same type). Smaller ones are charged
    there too, so a module with many such conditionals reaches its function work sooner
    (T-0114e).
  - Conditionals now count as walking their inputs, so they draw on the module's function work
    like calls do.
  - The same quadratic unification remains in tuple-to-list conversions of function parameters
    (`tolist`) and variable type constraints (T-0114d).
