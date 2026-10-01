---
name: iace-architecture
description: Architecture, package layout and data contracts of iac-compliance-enforcer (iace), the Go + OPA Terraform compliance scanner. Covers the scan pipeline, the normalized input document that Rego policies consume, the finding model, CLI commands, flags and exit codes, dependency rules between packages, determinism, and the ADR process. Use this before creating packages or files, changing any contract (input document, findings, config, CLI, exit codes), adding a component, or whenever you are unsure where code belongs. Load it even for small features that cross package boundaries.
---

# iace architecture

## Project identity
| item | value |
|---|---|
| Repository | github.com/thuansec/iac-compliance-enforcer (private), whose local working copy is this directory |
| Go module | `github.com/thuansec/iac-compliance-enforcer` |
| CLI binary | `iace` (decision D-02) |
| Per-repo config | `.iace.yaml` (schema `schemas/config.v1.json`, owned by `iace-repo-policy`) |
| Built-in rule IDs | `IACE-<CSP>-<SERVICE>-<NNN>`, e.g. `IACE-AWS-S3-001`. CSP ∈ AWS, AZURE, GEN. IDs are immutable and never reused. |
| Policy namespace | `iace.lib.*` for helpers, `iace.rules.<csp>.<service>.<rule>` for rules |
| Env var prefix | `IACE_` |

## What iace is (and is not)
iace statically checks Terraform for security and compliance misconfigurations in AWS and Azure,
using Rego policies evaluated by an embedded OPA. It runs locally, in pre-commit, and in CI, where it
gates pull requests. **Non-goals:** calling cloud APIs, running `terraform` on scanned code,
auto-merging fixes, and replacing runtime CSPM. These are boundaries, not omissions: each would
bring credentials, network access or code execution into a tool that must be safe to point at
untrusted pull requests.

## Pipeline
```
 discover ─► load ─────────────► normalize ─► select policies ─► evaluate ─► findings ─► exceptions ─► (AI suggest) ─► report ─► exit code
 roots      HCL (default)        input doc    builtin + pinned   OPA         located,    owner/reason/   opt-in, verified   text/json/   0 ok
            or plan JSON         v1 per root  verified bundles   prepared    fingerprint expiry          by re-scan         sarif/junit/  1 blocking
            (trusted pipeline)                + repo config      query                                                      md/github     2 error
```
Each stage is a package with a narrow API. Data flows forward only. No stage reaches back into
an earlier stage's internals.

## Package layout
```
cmd/iace/                 thin main(): builds the root command, maps errors to exit codes
internal/cli/             cobra commands and flags; the only place that reads flags/env and calls os.Exit
internal/app/             use-case orchestration (Scan, Inspect, Fix); wires the components; no I/O policy of its own
internal/model/           shared types: input document, Resource, SourceRange, Finding, Severity. No dependencies.
internal/terraform/       discovery, HCL parse, evaluation, module resolution, normalization (iace-terraform-parsing)
internal/terraform/plan/  plan JSON ingestion (M9)
internal/config/          .iace.yaml + org baseline loading, validation, merge (iace-repo-policy)
internal/policy/          policy sources: builtin embed, bundles; verification, cache (iace-repo-policy)
internal/engine/          OPA compile/prepare/eval, metadata, violation decoding (iace-opa-engine)
internal/exceptions/      exception matching and lifecycle
internal/report/          one sub-package per format plus the Reporter interface (iace-reporting)
internal/remediation/     AI suggestion interface, providers, redaction, fix validation (iace-ai-remediation)
internal/version/         build info set via -ldflags
policies/                 built-in Rego library and embed.go (iace-rego-policies)
schemas/                  JSON Schemas: input.v1, findings.v1, config.v1, ai-fix.v1
testdata/                 Terraform fixtures, golden files, fuzz corpora (iace-testing)
docs/adr/  docs/plan/     decisions; backlog and progress
tools/go.mod              pinned dev tools
```
**Dependency rules** (enforce with depguard or tests if they drift):
- `model` imports nothing internal. Everything may import `model`.
- Components (`terraform`, `config`, `policy`, `engine`, `exceptions`, `report`, `remediation`)
  never import each other's internals. `app` wires them through small interfaces that the
  consuming package defines.
- Only `cli` touches `os.Args`, env vars, `os.Exit`, and the decision of where stdout/stderr go.
  Everything else receives `io.Writer`s, a `fs.FS` or root path, a clock, and a `context.Context`.
- `remediation` is the only package that may hold an API client, and the scan path has zero
  network access unless policy sources or AI are explicitly configured.

## Contracts
These are the interfaces between components and between Go and Rego. Changing one is a design
change: update the reference document, the JSON Schema and the golden tests, and add an ADR,
all in the same commit.
- **Input document v1**, the Go → Rego contract: [references/input-document.md](references/input-document.md)
- **Finding v1, CLI and exit codes**: [references/findings-and-cli.md](references/findings-and-cli.md)
- **Config v1** (`.iace.yaml`): `iace-repo-policy` skill
- **Rule metadata**: `iace-rego-policies/references/metadata-schema.md`

## Cross-cutting requirements
- **Fail closed.** Any parse, config, policy-compile or evaluation error exits 2 with a message that
  names the file and rule. Unknown or unchecked parts of the scan are reported as *coverage gaps*,
  never silently treated as compliant.
- **Determinism.** The same inputs produce byte-identical outputs. Sort findings (severity desc,
  rule ID, file, line, address), emit JSON keys in a stable order, use no map-iteration order in
  output, take time only from an injected clock, and use no randomness. Golden tests depend on this.
- **Offline by default.** Scanning needs no network. Network use happens only for configured
  remote policy bundles and opt-in AI, both with timeouts and size limits.
- **Secrets never leave.** Attribute values marked sensitive, and values matching secret patterns,
  never appear in logs, reports, or AI prompts.
- **Performance budgets.** 1k resources in under 2 s and 5k resources in under 10 s, under 1 GiB of
  memory, on a 4-core runner. Compile policies once per run and evaluate root modules
  concurrently, bounded by GOMAXPROCS.
- **Versioned outputs.** Every machine-readable output carries `schema_version`. Additive changes
  are minor; renames and removals need a new major schema and an ADR.

## Extension points
| to add… | implement | registered in |
|---|---|---|
| an output format | `report.Reporter` | `internal/report/registry.go` |
| a policy source type | `policy.Source` | `internal/policy/sources.go` |
| an AI provider | `remediation.Suggester` | `internal/remediation/providers.go` |
| a CSP | provider prefix → CSP map, plus `policies/iace/rules/<csp>/` and a catalog in `iace-cloud-controls` | `internal/terraform/providers.go` |

## ADRs
Write an ADR (`docs/adr/NNNN-kebab-title.md`, template in
[references/adr-template.md](references/adr-template.md)) when you choose between real
alternatives, change a contract, add a significant dependency, or accept a security trade-off.
Keep it under a page. ADRs are immutable: supersede an old one instead of editing it.
