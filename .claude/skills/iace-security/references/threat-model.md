# iace threat model (seed; T-0007 copies it to docs/security/threat-model.md)

## Assets
- A1 **Integrity of verdicts**: pass/fail must reflect the real configuration and policies.
- A2 **CI secrets and tokens** available to the job running iace (GITHUB_TOKEN, cloud OIDC, AI keys).
- A3 **Secrets inside scanned Terraform** (hardcoded passwords, keys).
- A4 **Policy library and bundles**, which decide A1.
- A5 **Release artifacts** (binary, action, policy bundles).
- A6 **Availability** of CI (a scan must not hang or exhaust runners).

## Actors
- PR author (untrusted; controls scanned files, `.iace.yaml`, module contents)
- Compromised dependency or action maintainer
- Network attacker (bundle download, AI traffic)
- Malicious or compromised policy-bundle publisher
- The AI model when steered by injected content

## Threats and mitigations (STRIDE-oriented)
| # | threat | asset | mitigation | test |
|---|---|---|---|---|
| T1 | Code execution via Terraform (providers, `external` data sources, provisioners, module fetch) | A2 | static analysis only; never run terraform on scanned code; plan JSON is accepted only from trusted pipelines | e2e: provisioner and `external` fixtures produce findings, no process spawned (exec hook in tests) |
| T2 | Path traversal or symlink escape from the scan root (`../` module source, symlinked dirs) | A2, A3 | `os.Root` confinement; validated relative paths | adversarial fixtures |
| T3 | DoS through huge, deep or recursive inputs (count = 1e9, deep nesting, recursive modules, zip bombs) | A6 | limits on every dimension, plus timeouts → gap or exit 2 | limit tests at the boundaries |
| T4 | Verdict tampering via repo config (disable rules, everlasting exceptions, add trusted keys) | A1 | strict schema; exceptions need owner, reason and bounded expiry; org baseline may only tighten; keys never from repo config; CODEOWNERS | config and baseline tests |
| T5 | Malicious or tampered policy bundle | A1, A4 | sha256 pin, ES256 signature, trust store from trusted inputs only, namespace roots, restricted capabilities (no network builtins), strict compile | tamper, wrong-key and overlap tests |
| T6 | Silent pass through policy bugs (typo'd attribute, unknown treated as pass, eval error swallowed) | A1 | metadata validation; strict decoding; fail-closed eval errors; fixture harness completeness; schema-validated fixtures; coverage ≥ 90% | harness, engine error tests |
| T7 | Secret disclosure in reports, logs, caches, or to the AI provider | A3 | message rules; sensitive-path redaction; secret-pattern redaction before AI; no value logging; 0600 caches | secret fixtures absent from every output |
| T8 | Prompt injection steering AI to weaken infra or hide findings | A1 | advisory only; schema-limited output; validator (dangerous constructs, re-scan, no unknown-ization, resource must remain); never auto-applied in CI | injection fixtures in validator tests |
| T9 | Credential leakage over the network (token sent to the wrong host on redirect) | A2 | host allowlist; Authorization stripped on host change; HTTPS only | httptest redirect tests |
| T10 | Supply-chain compromise of iace (deps, actions, release) | A5 | pinned deps and SHAs, govulncheck, Dependabot, reproducible signed releases, provenance, protected environments | CI policy checks, actionlint |
| T11 | Workflow injection in consumer or own workflows (`${{ github.event… }}` in run) | A2 | env indirection, actionlint, no `pull_request_target` with PR code | actionlint and review checklist |
| T12 | Report spoofing in PR (an attacker-crafted resource name or message breaking Markdown or annotations) | A1 | escape Markdown, annotation properties and SARIF text; addresses rendered as code | golden tests with hostile names |

## Out of scope (documented)
- Runtime cloud posture (no cloud API access by design).
- Compromise of the CI runner itself, or of GitHub.
- Correctness of provider plugins' runtime behaviour.

## Review cadence
Update this file whenever a trust boundary, asset or mitigation changes (the security checklist
item), and fully at T-1105 before the first release.
