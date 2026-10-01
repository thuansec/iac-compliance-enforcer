# iace skills

Project skills for building **iac-compliance-enforcer (`iace`)**, a Go and OPA scanner for
Terraform security compliance on AWS and Azure, through an autonomous development loop.
Claude Code loads each `iace-*/SKILL.md` automatically. This README is for humans and is not a skill.

## How the loop uses them
```
/loop /iace-loop            (or headless: claude -p "/iace-loop" in a shell loop)
   │
   ▼
iace-loop ── orient → select task (docs/plan/BACKLOG.md) → plan → test first → implement → verify → record → commit
   │             │                                          │                       │
   │             └─ loads the skills listed on the task ────┘                       └─ iace-quality-gates (gates.sh full)
   ▼
next iteration … pauses at each milestone for human approval
```

## Skills
| skill | role | key bundled files |
|---|---|---|
| `iace-loop` | entry point: one task per iteration, bootstrap, backlog rules, stop conditions | `references/roadmap.md` (seed backlog: 12 milestones, 92 tasks), `scripts/loop_status.py` |
| `iace-architecture` | pipeline, package layout, contracts, exit codes, ADRs | `references/input-document.md` (Go→Rego contract), `findings-and-cli.md` |
| `iace-go-standards` | Go toolchain, idioms, errors, logging, deps and licenses | `assets/golangci.yml` (v2) |
| `iace-terraform-parsing` | static HCL loading, evaluation, modules, plan JSON; never executes Terraform | `references/hcl-evaluation.md`, `plan-json.md` |
| `iace-opa-engine` | embedded OPA v1, restricted capabilities, prepared query, fail-closed decoding | `references/capabilities.md` |
| `iace-rego-policies` | how to write and test rules: unknowns, defaults, provider majors | `assets/policies/` (helper lib + template rule, with tests; verified), `assets/regal-config.yaml` |
| `iace-cloud-controls` | AWS and Azure control catalog with verified defaults and mappings | `references/aws.md`, `azure.md`, `frameworks.md`, `scripts/provider_schema.sh` |
| `iace-repo-policy` | `.iace.yaml`, exceptions (owner/reason/expiry), org baseline, signed policy bundles | `references/config-schema.md`, `policy-supply-chain.md` |
| `iace-reporting` | text, JSON, SARIF (GitHub), JUnit, Markdown, annotations | `references/sarif.md` |
| `iace-ci-cd` | this repo's CI/release plus PR enforcement (Action, code scanning, rulesets) | `references/consumer-workflow.md`, `release.md` |
| `iace-ai-remediation` | opt-in AI fix suggestions, verified by re-scanning | `references/prompt-contract.md` |
| `iace-testing` | test-first, fixture harness, golden, testscript, fuzz, benchmarks | — |
| `iace-security` | trust boundaries, secure coding, supply chain, review checklist | `references/threat-model.md` |
| `iace-quality-gates` | definition of done, Makefile contract, self-review | `scripts/gates.sh` |

## What was verified while writing these (2026-10-01)
- Rego templates: `opa fmt`, `opa check --strict` with restricted capabilities, `opa test` 18/18
  passing with 100% coverage (OPA 1.21.1), and `regal lint` clean (Regal 0.43.0). A capabilities file without network builtins blocks
  `http.send` at compile time but keeps `net.cidr_*`. ES256 bundle signing and verification
  round-trips with `opa build`.
- Provider defaults: aws 6.67.0, azurerm 4.81.0 and 5.7.0 docs, via `provider_schema.sh docs`.
  AWS Security Hub control IDs: from AWS's control reference pages.
- GitHub: `upload-sarif@v4`, SARIF `security-severity` mapping and limits, permissions for
  private repos, ruleset code-scanning merge protection.
- Scripts: `loop_status.py` across bootstrap, fresh, blocked and JSON states; `gates.sh` across
  bootstrap, stub-Makefile, failing-target, secret, skip, TODO and missing-tool cases (fails closed).

## Before starting the loop
1. Review `iace-loop/references/roadmap.md` (milestones, order, acceptance criteria) and the
   *Decisions needed* list in it.
2. Toolchain (installed 2026-10-01, user-level in `~/.local`, every download checksum-verified):
   Go 1.27.1, golangci-lint 2.14.0, govulncheck 1.8.0, actionlint 1.7.12, Regal 0.43.0, OPA 1.21.1,
   plus the existing Terraform 1.13.2, jq, Python 3, git, make and gh. The loop pins its own tool
   versions in `tools/go.mod` (T-0002); these global copies are for manual use.
3. GitHub access: `git ls-remote https://github.com/thuansec/iac-compliance-enforcer.git` must
   work. With a fine-grained token, the repository must be in the token's *Repository access*,
   with Contents and Workflows read & write (see `iace-loop/references/bootstrap.md`).
4. Run `/iace-loop bootstrap` once, then `/loop /iace-loop`.
