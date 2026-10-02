# `.iace.yaml` v1

## Annotated example
```yaml
# iac-compliance-enforcer repository policy. Changes require security review (CODEOWNERS).
version: 1

policies:
  csps: [aws, azure]            # default: detected from the providers in use
  frameworks: []                # only rules mapped to these keys (iace-cloud-controls/references/frameworks.md)
  min_severity: low             # rules below this are not evaluated (critical|high|medium|low|info)
  builtin: true                 # embedded built-in library; false only when pinning the central library
  disabled_rules:               # switching a rule off is accountable and temporary
    - id: IACE-AWS-ELB-001
      reason: Internal ALBs terminate TLS in the service mesh; tracked in PLAT-88
      owner: "@acme/platform"
      expires: 2027-03-31

thresholds:
  fail_on: high                 # exit 1 when an open finding is at or above this (none = never)
  max_exception_days: 90        # may only be lower than the org baseline's value

sources:                        # extra policy bundles, pinned and verified (M8)
  - name: acme
    url: https://github.com/acme/iace-policies/releases/download/v1.4.0/acme-policies.tar.gz
    sha256: 9f2c4e…64 hex…
    key_id: acme-policies-2026  # must exist in the CI-provided trust store

rule_params:                    # validated against each rule's custom.params schema (M4, optional)
  ACME-GEN-TAGS-001:
    required_tags: [owner, environment, data-classification]

paths:
  exclude:                      # excluded paths are listed in reports as coverage gaps
    - glob: "examples/**"
      reason: Documentation snippets, never deployed

exceptions:
  - id: EXC-0001
    rules: [IACE-AWS-S3-002]
    resources: ["module.site.aws_s3_bucket_acl.public"]
    paths: ["web/**"]
    reason: Public marketing site; bucket only holds published static assets
    owner: web-team@acme.example
    ticket: SEC-1234
    expires: 2026-12-31

ai:                             # opt-in AI fix suggestions (M10)
  enabled: false
  provider: bedrock             # Amazon Bedrock, the only approved provider (D-05); region comes from the AWS environment
  model: anthropic.claude-opus-5-5
  min_severity: high
  max_findings: 20
```

## Validation rules
| field | rule |
|---|---|
| `version` | required, `1` |
| `policies.csps` | subset of `aws`, `azure`, `generic` |
| `policies.min_severity`, `thresholds.fail_on` | enum; `fail_on` may also be `none` |
| `disabled_rules[]` | `id` must exist among loaded rules (else a warning: the rule may come from a source not loaded); `reason` ≥ 15 chars; `owner` matches email or `@user` / `@org/team`; `expires` ISO date within `max_exception_days` |
| `thresholds.max_exception_days` | 1–365, and ≤ the org baseline |
| `sources[]` | `name` `^[a-z][a-z0-9-]{1,30}$`, unique; exactly one of `url` (https only) or `path` (inside the repo); `sha256` 64 lowercase hex, **required**; `key_id` required |
| `rule_params` | keys are rule IDs; values validated against the rule's `custom.params` JSON Schema |
| `paths.exclude[]` | `glob` (doublestar syntax, relative, no `..`), `reason` required |
| `exceptions[]` | see the iace-repo-policy SKILL.md exceptions section; IDs `^EXC-[A-Za-z0-9-]{1,40}$`, unique |
| `ai` | `enabled` bool (default false); `provider` enum: `bedrock` only; `model` string (a Bedrock model ID); no region key; `min_severity` enum; `max_findings` 1–200 |

Error messages cite `file:line:column` and the offending key path (`exceptions[2].expires`) and
suggest the fix ("expires must be on or before 2026-12-30 (max_exception_days 90)").

## JSON Schema
`schemas/config.v1.json` (Draft 2020-12) is the source of truth for structure. Semantic rules
(dates relative to the clock, loaded-rule existence, org-baseline limits) live in Go and are
tested separately. Publish the schema URL in the file header comment that `iace init` writes,
so editors with YAML language servers give completion.
