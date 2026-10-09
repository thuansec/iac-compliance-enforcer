# 0024 · Evaluate .tf.json values member by member

- Status: accepted
- Date: 2026-10-09
- Task: T-0113b
- Amends: ADR 0020 (for expressions in nested .tf.json template strings)

## Context
ADR 0020 charges for-expression iterations by rewriting the syntax trees iace evaluates. hcl's
JSON decoder parses a template string only while it evaluates a value. So iace evaluated a
value that is one template string itself (jsonStringTemplate), but refused, as too complex, a
for expression in a template string nested in a JSON object or array. Generated .tf.json uses
such templates, for example in tags and map arguments.

## Decision
- Every .tf.json value evaluated with a context is evaluated by iace member by member
  (evalJSON), as hcl's JSON decoder evaluates it. This includes values without a for expression:
  hcl's decoder panics on a sensitive object key (`{"${var.s}": 1}` with a sensitive var.s), a
  crash that untrusted input could trigger (T-0113b review).
  - Arrays become tuples, element by element.
  - Objects become objects. Their keys are templates too; a key that is null or not a string is
    an "Invalid object key expression" error, a duplicate key is a "Duplicate object attribute"
    error, and an unknown key makes the whole object unknown.
  - Each template string is parsed from the byte after its opening quote and rewritten
    (jsonStringTemplate), so its for expressions are charged as in HCL. Numbers, booleans and
    null are evaluated by hcl.
  - A sensitive key is an error, where hcl's decoder would panic.
- Without a context, JSON strings stay literal, as before (hcl evaluates the value).
- Template strings are rewritten as HCL trees are, so `lookup` in a JSON template is also
  `__iace_lookup` (ADR 0023).

## Alternatives considered
- Keep refusing nested for expressions: generated JSON then loses values that are small and
  harmless.
- Rewrite hcl's JSON syntax tree in place: its node types are unexported.

## Consequences
- Positive: for expressions anywhere in a .tf.json value are evaluated and bounded.
- Positive: a sensitive object key is an error diagnostic, not a crash
  (TestJSONSensitiveKeysAreErrors).
- Negative / accepted risks: iace now has its own evaluation of JSON objects and arrays, used for
  every JSON value it evaluates. A test (TestEvalJSONMatchesHCL) compares it with hcl's on values
  and errors, so a change in hcl's JSON semantics shows up there.
