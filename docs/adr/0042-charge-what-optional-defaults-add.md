# 0042 · Charge what optional() defaults add to a value

- Status: accepted
- Date: 2026-10-13
- Task: T-0116l
- Extends: ADR 0036, ADR 0041

## Context
Before converting a variable's value to its type, typeexpr inserts each optional() default into
every object that lacks the attribute. The conversion estimate (chargeConversion,
conversionCostDone) runs on the value before the defaults are inserted, so it never sees what
they add. Take `type = set(object({ k = string, s = optional(set(string), [200 strings]) }))`
with 300 small objects. The variable was declared with no diagnostic, and its first use then
sorted a set of 300 elements that each hold a 200-string set: the locals took 4.1 s (T-0116i
review: 4.4 s for one length() over 100).

## Decision
- chargeConversion adds defaultsGrowthCost to the estimate when the type has defaults, unless
  the estimate is already past the limit:
  - each object or map in the value (objectCount, which stops at the limit) is charged the size
    and walk sort (valueSizeWalk) of the most the type's defaults can insert into one object
    (insertedWeight);
  - an object takes only the defaults of the one node of the type its place matches, so
    insertedWeight is the largest of the nodes' insertions. A node inserts each of its default
    values, and typeexpr grows each one by applying the child defaults to it
    (Children[key].apply): so a default counts its own size, plus its objects times the most the
    child's subtree can insert into one object. Each node is computed once, so the work is
    linear in the type. A chain of nested optional objects costs about its depth, while defaults
    that hold many objects with defaults multiply. The result saturates, so such defaults are
    refused rather than counted. The review showed why a flat sum of the defaults is no bound:
    40 elements whose default holds 50 objects, each with a 200-string set default, were
    declared after 3 s and then took 43.8 s for two length() locals. Four levels of 30-object
    list defaults took about 9 minutes on main. A first recursive version computed each child
    once per use, which doubles per level: a 30-line type could hang the scan (review again);
  - when the type holds a set whose elements hold sets, the outer set's first sort is charged as
    valueSizeWalk prices it: per element and level, the inserted size plus nestedSortFactor times
    the inserted sorts.
- A first attempt charged the grown value's weight squared, as setBuildCost does for sets of
  sets. It refused 100 ordinary security group rules that had small optional defaults, which
  main accepts. The walk model accepts 200 such rules.
- In the 200-string case, the largest values accepted (about 40 elements) are walked in 0.4 to
  0.55 s on first use, about 100 ns per unit charged. 300 elements are refused at declaration,
  and so are both nested cases.

## Consequences
- A variable whose defaults make a costly set of sets is refused where it is made, with
  value_too_large. Its first use no longer pays the sort.
- Module inputs go through the same conversion (finishVariable → chargeConversion) and are
  charged the same way (TestModuleInputDefaultsInsideSetsAreCharged).
