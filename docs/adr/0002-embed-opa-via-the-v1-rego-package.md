# 0002 · Embed OPA via the v1 rego package

- Status: accepted
- Date: 2026-10-02
- Task: T-0005

## Context
iace evaluates Rego compliance policies against a normalized view of Terraform. It has to ship as
one static binary that runs offline on laptops and in CI, give identical results everywhere, fail
closed on any policy error, and stay fast (5,000 resources in under 10 seconds). Policies come
from the built-in library and from pinned, signature-verified bundles, so iace itself must
control compilation, capabilities (no network or nondeterministic builtins) and evaluation
deadlines.

## Decision
Embed Open Policy Agent as a Go library through `github.com/open-policy-agent/opa/v1/rego`
(with `v1/ast` and `v1/bundle`), not through the `sdk` package and not as an external process.
Compile once per run in strict mode with a restricted capabilities file, prepare one query that
goroutines share, and evaluate each root module under a deadline. The `opa` CLI used for
`opa test` and `opa check` is pinned in `tools/opa/go.mod` to exactly the library version in
`go.mod` (v1.21.1 today), and the two are always bumped in one commit. Pre-v1 import paths are
banned by depguard.

## Alternatives considered
- Running the `opa` binary or conftest as a subprocess: a second artifact to ship and verify,
  slower per evaluation, and weaker control over capabilities and error handling.
- OPA's `sdk` package: built for long-running agents (discovery, decision logs, bundle polling),
  none of which iace wants.
- A non-Rego engine (checks coded in Go, CEL, or Python as in Checkov): it gives up
  policy-as-code and the separation between rule authors and engine code.

## Consequences
- Positive: one binary; the same engine in policy tests and in production; full control over
  capabilities, deadlines and errors.
- Negative / accepted risks: OPA brings a large dependency tree that upgrades and govulncheck
  must keep up with; every OPA upgrade regenerates the capabilities file and re-runs the full
  policy suite.
- Follow-ups: T-0201 (policy library and capabilities), T-0202 to T-0204 (engine).
