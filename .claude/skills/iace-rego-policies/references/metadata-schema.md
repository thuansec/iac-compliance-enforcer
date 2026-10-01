# Rule metadata schema

A package-scoped `# METADATA` block placed directly above `package`. YAML inside comments.

```rego
# METADATA
# title: EC2 instances must require IMDSv2
# description: >-
#   Why this matters: the risk, in 1–3 sentences.
# scope: package
# related_resources:
#   - ref: https://docs.aws.amazon.com/...
#     description: Short label
# custom:
#   id: IACE-AWS-EC2-001
#   severity: high
#   csp: aws
#   service: ec2
#   resource_types: [aws_instance]
#   frameworks:
#     aws-securityhub: [EC2.8]
#   remediation: Add metadata_options { http_tokens = "required" } to the instance.
#   params: {}                 # optional JSON Schema for data.iace.params[<id>] (M4)
#   deprecated: false          # optional
#   replaced_by: ""            # optional
package iace.rules.aws.ec2.imdsv2_required
```

## Field rules (validated by the engine at load time)
| field | rule |
|---|---|
| `title` | required; ≤ 80 chars; states the requirement ("… must …") |
| `description` | required; states the risk, not the mechanics |
| `related_resources` | ≥ 1 entry; `ref` is an https URL to vendor docs or the control reference |
| `custom.id` | required; `^IACE-(AWS\|AZURE\|GEN)-[A-Z0-9]+-\d{3}$` for built-ins; external bundles use their own prefix `^[A-Z][A-Z0-9]+-[A-Z0-9-]+$` and may not use `IACE-` |
| `custom.severity` | required; `critical\|high\|medium\|low\|info` |
| `custom.csp` | required; `aws\|azure\|generic` |
| `custom.service` | required; lowercase short name matching the package segment |
| `custom.resource_types` | required; non-empty list of Terraform types the rule inspects |
| `custom.frameworks` | optional map: framework key → list of control IDs (keys in `iace-cloud-controls/references/frameworks.md`); only **verified** mappings |
| `custom.remediation` | required; one or two sentences with the concrete Terraform change |
| `custom.params` | optional JSON Schema object; config values are validated against it |

Unknown `custom.*` keys are rejected (they are usually typos), except keys starting with `x_`.

## Severity rubric
Decide by **impact if exploited × how directly the misconfiguration exposes it**, not by how
common the issue is.

| severity | use when | examples |
|---|---|---|
| critical | direct, unauthenticated exposure of data or control from the internet, or full account/subscription compromise | public-write bucket ACL; IAM `*:*` admin policy; SQL firewall 0.0.0.0–255.255.255.255 |
| high | an exploitable weakness or broad exposure needing one more step | SSH/RDP open to the internet; IMDSv1; public RDS; AKS API open to the world; anonymous blob access |
| medium | a missing defense-in-depth control, or weak crypto in transit | storage without TLS 1.2 minimum; KMS rotation off; Key Vault purge protection off; CloudTrail validation off |
| low | hygiene with limited direct risk | access logging off; versioning off |
| info | advisory; never blocks by default | deprecated-but-safe settings |

The SARIF `security-severity` mapping is in `iace-reporting/references/sarif.md`.
