---
name: iace-opa-engine
description: How iace embeds Open Policy Agent in Go — the v1 rego/ast/bundle packages, loading and parsing policy modules with METADATA annotations, metadata validation, restricted capabilities (no network or nondeterministic builtins), strict compilation, a single prepared query shared across goroutines, evaluation with timeouts, strict violation decoding into findings, and fail-closed error handling. Use this for any work in internal/engine, when wiring policies into scans, upgrading OPA, debugging a policy that does not fire or errors at runtime, or tuning evaluation performance.
---

# Embedding OPA

## Library choice
- Import `github.com/open-policy-agent/opa/v1/rego`, `.../v1/ast` and `.../v1/bundle`. The
  pre-v1 import paths are banned by depguard.
- Use the low-level `rego` package, not `sdk`. OPA's own docs recommend `rego` when "only policy
  evaluation — and no other capabilities of OPA, like the management features — are desired",
  which is our case: no discovery, no decision logs, no remote bundle polling.
- Keep the library version equal to the `opa` CLI pinned in `tools/go.mod`, and bump both in one
  commit. Re-run `make capabilities` and the full policy suite on every bump.

## Lifecycle (once per run)
```
sources ──► modules (map[path]src, *_test.rego excluded)
        ──► ast.ParseModuleWithOpts(path, src, ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV1})
        ──► validate metadata  (fail closed)
        ──► rego.New(rego.Query(q), rego.ParsedModule(m)…, rego.Capabilities(caps),
                     rego.Strict(true), rego.StrictBuiltinErrors(true), [rego.Store(data)])
        ──► PrepareForEval(ctx)  → one PreparedEvalQuery, shared read-only across goroutines
per input document:
        ──► v := ast.InterfaceToValue(doc)          (once per document)
        ──► pq.Eval(ctxWithTimeout, rego.EvalParsedInput(v))
        ──► decode violations strictly → []Finding
```
OPA documents prepared queries as safe to share across goroutines. Evaluate root modules
concurrently with a bounded errgroup (`iace-go-standards`).

## Rule discovery and the query
- A **rule package** is any package under `iace.rules.` (built-in and external sources alike).
  Each must:
  1. carry a package-scoped `# METADATA` block valid against
     `iace-rego-policies/references/metadata-schema.md`, and
  2. define a partial set rule named `deny`.
  A package that fails either check, or a duplicate `custom.id` across all loaded sources, is a
  load error naming the file(s) and source(s). Never skip such a package silently. A skipped rule
  is an unenforced control.
- Build **one** query from the discovered packages, keyed by rule ID:
  `x := {"IACE-AWS-EC2-001": data.iace.rules.aws.ec2.imdsv2_required.deny, …}`.
  One evaluation per input document returns everything. Because every package is verified to
  define `deny`, the object can never be undefined. If `x` comes back undefined, treat it as an
  internal error, not "no findings".
- Disabled rules (repo config) are removed from the query, not filtered afterwards, so they cost nothing.

## Capabilities: what policies may call
Policies must be pure functions of `input` and `data`. Restrict builtins with a capabilities
file generated from the pinned OPA version minus a denylist. Generation recipe and denylist:
[references/capabilities.md](references/capabilities.md). The same `policies/capabilities.json` is:
- embedded and passed via `rego.Capabilities` (runtime), and
- passed to `opa check/test --capabilities` (CI), so authors see the error at commit time.

A policy calling a removed builtin fails compilation with `rego_type_error: undefined function`.
That is the desired fail-closed behaviour.

## Data documents
`data.iace.params[<rule-id>]` holds rule parameters from config (M4), validated before load.
Keep data small, provide it through `rego.Store(inmem.NewFromObject(...))`, and never let it carry
secrets. External bundles may ship data only under their own manifest roots.

## Violation decoding (strict)
Each element of a rule's `deny` set must be an object with:
- `address` (string, **required**, must equal the `address` of a resource in that input document)
- `message` (string, required, non-empty, at most 500 chars)
- `attribute_path` (array of strings and integers, optional)

Anything else is a `PolicyError{RuleID, Detail}` and exit 2. A policy that emits garbage is
broken, and pretending otherwise hides missed controls. Unknown extra keys are ignored for
forward compatibility, but logged at debug level.

Build findings from the decoded violation plus rule metadata plus the resource's source map
(the attribute range when `attribute_path` resolves, else the block range). Compute the
fingerprint as specified in `iace-architecture/references/findings-and-cli.md`.

## Errors and timeouts
| failure | handling |
|---|---|
| parse or compile error | `PolicyError` with file:line from `ast.Errors`; exit 2 |
| builtin error at eval time (`StrictBuiltinErrors`) | `PolicyError` naming the rule (map the error location's file to the rule ID); exit 2 |
| conflicting complete-rule outputs | same as above, since it means a policy bug |
| context deadline (default 30s per document, `--timeout` overall) | `EvalTimeoutError`; exit 2 |
| undefined query result | internal error; exit 2 |

Never retry evaluations. They are deterministic, so a retry only hides the bug.

## Debugging policies
- `print()` is allowed by capabilities but compiled out unless `--debug-policies` sets
  `rego.EnablePrintStatements(true)` with a `rego.PrintHook` that writes to slog at debug level.
  Regal blocks print calls in committed policies.
- `iace inspect <path> --json > input.json`, then `opa eval -d policies -i input.json 'data.iace.rules…'`,
  reproduces a scan in the OPA CLI.

## Performance
- Parse, compile and prepare once per run. Convert the input once per document (`EvalParsedInput`).
- Prefer rules that filter by `r.type` first, which lets the comprehension work over a small set.
  Avoid `walk(input)` and O(n²) joins in policies (`iace-rego-policies`).
- Benchmark with `BenchmarkEvaluate` (synthetic documents of 1k and 5k resources, all built-in rules)
  and keep the result inside the `iace-architecture` budget.

## Tests to keep
- metadata validation: one table case per invalid field; a duplicate ID across two sources
- a policy using `http.send` → compile error (capabilities enforced at runtime too)
- a policy emitting a violation with an unknown address, or no message → `PolicyError`
- builtin error at runtime → exit-2 path, with the rule ID in the message
- timeout path with a deliberately slow policy (bounded recursion over a big input)
- concurrency: evaluate the same prepared query from many goroutines under `-race`
