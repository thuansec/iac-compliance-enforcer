# 0034 · Charge a conditional's conversions exactly

- Status: accepted
- Date: 2026-10-11
- Task: T-0114k
- Extends: ADR 0030, ADR 0032

## Context
ADR 0030 charged a conditional whose result types differ as unifying the two types plus
converting each result, estimated with valuePart: every tuple, object or map in a result cost
unifying its element types, whatever the target. That refused
`true ? <40,000 repeated strings> : toset(["b"])`, whose conversion is linear (T-0116 review).

Two more over- and under-counts came out of measuring it:
- `unifyAt` charged every mix of structural kinds as unifying all their element types together.
  cty's `unify` does that only on its structural paths: all maps, maps and objects, all lists,
  lists and tuples, all sets, all objects and all tuples. Other mixes, such as a tuple and a set,
  go to its general path. That path sorts the types and tries each one as the result, building
  conversions from the others. Building them walks the types but unifies nothing, unless a
  target holds `any`. A 40,000-element tuple and a `set(string)` unify in 0.6 ms, but were
  charged the whole module budget.
- T-0116's set build counted hashing in `walked`, which counts only beside another cost. So
  building a set of distinct values was free. Converting 40,000 distinct strings into a set
  takes about 27 ms (about 680 ns per element).

## Decision
- condConversionCost charges the unification (unifyTypesCost). When the types differ, it
  charges the unification again, because finding the unified type with convert.UnifyUnsafe
  repeats the work hcl does next. When they unify, it adds conversionCost of each result into
  that type, the type hcl converts to. Types that do not unify make hcl fail before converting, so only the
  unification is charged. Only the taken result is converted, so this can over-count by the
  other.
- unifyAt charges mixes outside cty's structural paths as mixed types already were: pairs ×
  the largest type, plus the walk. Mixes in which some type holds `any` keep the conservative
  charge, because converting a tuple into a set of `any` unifies its element types. Objects
  mixed with tuples fail at once and cost only the walk.
- setBuild charges each element its comparison weight plus setInsertWork (4) as cost. In a
  timing sweep that is 40 to 120 ns per unit for strings, numbers, repeated and mixed values.
  Objects of lists measure about 200 ns per unit: their element conversions unify nothing and
  so cost nothing, the gap ADR 0032 accepts.

## Consequences
- The conditional of repeated strings and a set is known. Quadratic conversions (maps of lists,
  colliding sets) stay refused.
- Every conversion into a set type now pays a linear charge, about the value's size plus four
  units per element. Typical tfvars and locals sets stay far inside the module budget.
- valueConversionCost (ADR 0030's estimate) is no longer used by evaluation.
- Iterating a set of compound values makes cty hash elements on every sort comparison, and
  nothing charges that later walk (length(), argument measuring). Such a set was reachable
  before, from a tfvars variable. Conditionals now accept more of them. Follow-up T-0116d.
