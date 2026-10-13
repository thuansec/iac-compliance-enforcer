# 0040 · Bound sets of sets where they are made

- Status: accepted
- Date: 2026-10-13
- Task: T-0116i
- Extends: ADR 0036, ADR 0039

## Context
cty sorts a set every time it iterates it. When the set's elements hold sets, each comparison
in that sort hashes both elements, which iterates, and so sorts, every set inside them. All of
that happens before a walk sees a single element, so no walk can count it as it goes. One walk
of a set of 100 sets of 200 strings took 2.7 s (T-0116d sweep). valueSizeWalk's up-front
estimate sees only the type `set(set(string))`. The inner sets cannot be measured without
iterating the outer set, because cty gives no access to a set's elements without sorting it.

## Decision
- Such values are bounded where they are made. Every path that makes a set whose elements hold
  sets charges building it as if every element collided: setBuildCost charges its weight
  squared, from the setBuild of a conversion or from the set functions' before-cost. This
  covers:
  - variable values (defaults, tfvars, --var, module inputs), through chargeConversion;
  - function arguments, such as toset and setunion;
  - conditionals.

  A set of sets that is made therefore holds at most about 2,900 units of weight (the square
  root of the module's work) and walks in microseconds. Larger ones are refused before cty
  builds them, in under a second, through each of those paths
  (TestSetsOfSetsAreBoundedWhereTheyAreMade).
- Two variable paths make sets of sets without that charge, and T-0116k bounds them. The review
  found both:
  - typeexpr converts each `optional(T, default)` default to T itself, uncharged. A
    100 × 200 default of type set(set(string)) took 6.3 s to declare.
  - Defaults applied inside the elements of a set of objects rebuild the set with the defaults
    inserted, and only the input value is charged. One `length(var.t)` over 100 objects that
    each got a 200-string set default took 4.4 s.
- HCL literals, templates, for expressions and splats make only tuples, objects and lists.
  Plan JSON is not read yet; when it is, its sets of sets need the same bound where they are
  decoded.
- The conversion estimate's per-iteration sort (ADR 0039) now includes valueSizeWalk's nested
  term for sets whose elements hold sets: nestedSortFactor × the inner sets' sorts per level.
  It also charges the two walks of each element, comparisonWeight and the measurement, which
  sort the inner sets as well.

## Consequences
- Apart from the optional() default paths (T-0116k), the 2.7 s first walk can arise only from
  values built outside iace's evaluation, as tests build them. A future reader of plan JSON
  must keep the bound.
- Converting a set of sets now costs at least twice valueSizeWalk's sort of it.
