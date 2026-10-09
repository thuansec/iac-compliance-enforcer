# iace threat model

iace is pointed at untrusted pull requests, often in CI next to tokens. A bug that executes
scanned code, leaks a secret, or reports "compliant" by mistake is a security incident. This
document lists what we protect, from whom, and how. iace is in early development, so each
mitigation says whether it is **in place** or **planned** in a milestone of the
[backlog](../plan/BACKLOG.md).

## Assets
- A1 **Integrity of verdicts**: pass and fail must reflect the real configuration and policies.
- A2 **CI secrets and tokens** available to the job running iace (GITHUB_TOKEN, cloud OIDC
  credentials, Amazon Bedrock credentials when AI suggestions are on).
- A3 **Secrets inside scanned Terraform** (hard-coded passwords and keys).
- A4 **Policy library and bundles**, which decide A1.
- A5 **Release artifacts**: the binary, the GitHub Action and policy bundles.
- A6 **Availability** of CI: a scan must not hang or exhaust runners.
- A7 **The development harness**: hooks, loop policy, rulesets and CI that constrain the AI agent
  that develops iace.

## Actors
- PR author (untrusted): controls scanned files, `.iace.yaml` and module contents.
- Compromised dependency or GitHub Action maintainer.
- Network attacker on bundle downloads and AI traffic.
- Malicious or compromised policy-bundle publisher.
- The AI model, when steered by injected content.
- The AI development loop, which acts with the owner's GitHub token and can be wrong.

## Threats and mitigations
| # | threat | asset | mitigation | status |
|---|---|---|---|---|
| T1 | Code execution via Terraform (providers, `external` data sources, provisioners, module fetch) | A2 | static analysis only; iace never runs terraform on scanned code; plan JSON is read only from trusted pipelines ([ADR 0003](../adr/0003-analyze-terraform-statically-never-execute-it.md)) | design in place; loader M1, plan JSON M9 |
| T2 | Path traversal or symlink escape from the scan root (`../` module sources, symlinked dirs) | A2, A3 | `os.Root` confinement; validated relative paths; adversarial fixtures; module sources and manifest directories confined without following symlinks ([ADR 0008](../adr/0008-bound-the-module-call-tree.md), [ADR 0013](../adr/0013-resolve-remote-modules-through-the-module-manifest.md)) | partly in place (M1) |
| T3 | Denial of service through huge, deep or recursive input (huge `count`, deep nesting, recursive modules, archive bombs) | A6 | limits on every dimension plus timeouts, each reported as a gap or exit 2; fuzzing; module call trees bounded to 32 levels and 1,000 calls, with symlinked module directories never followed ([ADR 0008](../adr/0008-bound-the-module-call-tree.md)); the evaluation work of a module tree bounded by tree budgets ([ADR 0009](../adr/0009-bound-the-evaluation-work-of-a-module-tree.md)) | partly in place (M1), fuzzing M11 |
| T4 | Verdict tampering via repo config (disabled rules, never-expiring exceptions, extra trusted keys) or committed tool state (a `.terraform/modules` manifest and module copies standing in for unresolved remote modules) | A1 | strict schema; exceptions need an owner, a reason and a bounded expiry; the org baseline can only be tightened; keys never come from repo config; the module manifest is used only when the pipeline trusts it, never by default or from `.iace.yaml` ([ADR 0013](../adr/0013-resolve-remote-modules-through-the-module-manifest.md)) | planned M4; manifest trust in place (M1) |
| T5 | Malicious or tampered policy bundle | A1, A4 | sha256 pin; detached ECDSA P-256 signature from a non-exportable AWS KMS key that only the tag-triggered release workflow can use; trust store from trusted inputs only; namespace roots; restricted capabilities; strict compile | planned M8 |
| T6 | Silent pass through policy bugs (misspelled attribute, unknown treated as pass, swallowed evaluation error) | A1 | metadata validation; strict decoding; evaluation errors fail closed; fixture harness completeness; Rego coverage ≥ 90% | planned M2 |
| T7 | Secret disclosure in reports, logs, caches or to the AI provider | A3 | message rules; sensitive-path redaction; secret-pattern redaction before AI; no value logging; 0600 caches | planned M3, AI redaction M10 |
| T8 | Prompt injection steering AI suggestions to weaken infrastructure or hide findings | A1 | AI is advisory only; schema-limited output; every fix is re-parsed and re-scanned before anyone sees it; never auto-applied in CI | planned M10 |
| T9 | Credential leakage over the network (a token sent to the wrong host on redirect) | A2 | host allowlist; Authorization stripped on host change; HTTPS only | planned M8 |
| T10 | Supply-chain compromise of iace (dependencies, actions, releases) | A5 | dependencies and actions pinned (actions by commit SHA); govulncheck and Dependabot; `main` and release-tag rulesets | in place; signed releases and provenance M11, bundle signing M8 |
| T11 | Workflow injection (`${{ github.event… }}` in `run:`) in our own or consumers' workflows | A2 | values pass through `env`; actionlint in CI; no `pull_request_target` with PR code | in place for this repository; the consumer action M5 |
| T12 | Report spoofing (an attacker-crafted resource name or message breaking Markdown or annotations) | A1 | escaped Markdown, annotation properties and SARIF text; addresses rendered as code; golden tests with hostile names | planned M3 |
| T13 | The AI development loop pushes unsafe changes, weakens a gate or leaks a secret | A7, A5 | hooks block secrets in commands, direct pushes to `main`, unverified commits, destructive git commands and GitHub writes; harness edits need the owner; an independent reviewer agent; the `main` ruleset requires a pull request with green CI for everyone; only the owner pushes tags | in place |
| T14 | Silent weakening through an override file (`main_override.tf` sets `acl = "public-read"` on a private bucket) | A1 | override files are reported as `override_not_merged` and become coverage gaps; `--fail-on-gaps` makes the scan exit 2 ([ADR 0005](../adr/0005-report-override-files-instead-of-merging-them.md)). Accepted risk until merging lands: without `--fail-on-gaps`, the scan passes with a reported gap | reported (T-0103), gap mapping T-0109, merging T-0112 |

## Out of scope
- Runtime cloud posture: iace has no cloud API access by design.
- Compromise of the CI runner itself, or of GitHub.
- How provider plugins behave at runtime.

## Keeping this current
Update this file whenever a trust boundary, asset or mitigation changes, and review it fully
before the first release (T-1105). Report vulnerabilities as described in
[SECURITY.md](../../SECURITY.md).
