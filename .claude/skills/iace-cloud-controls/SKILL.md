---
name: iace-cloud-controls
description: The AWS and Azure security-control catalog for iace's built-in Terraform policies — which resources and attributes to check, secure values, provider defaults and renames across supported provider majors (aws 5–6, azurerm 4–5), severity, priority, framework mappings (AWS Security Hub control IDs, Microsoft cloud security benchmark, CIS), and the protocol for verifying attribute names, defaults and mappings before writing a rule. Use this whenever choosing, implementing or reviewing an AWS or Azure rule, mapping a rule to a compliance framework, adding a new control to the backlog, or debugging a false positive caused by a provider default.
---

# Cloud control catalog

The catalog says **what** to check. `iace-rego-policies` says **how** to write it. Each catalog
entry becomes one backlog task and one rule.

- AWS: [references/aws.md](references/aws.md)
- Azure: [references/azure.md](references/azure.md)
- Framework keys and the mapping policy: [references/frameworks.md](references/frameworks.md)

## Supported provider majors
| provider | majors | notes |
|---|---|---|
| hashicorp/aws | 5.x, 6.x | 6.0 changed defaults (e.g. `aws_redshift_cluster` is now encrypted and not public by default) |
| hashicorp/azurerm | 4.x, 5.x | 5.0 (July 2026) removed deprecated names and changed defaults (blob public access off, TLS < 1.2 rejected, `public_network_access_enabled` → `public_network_access` on several resources) |

Policy for adding majors: when a new major ships, add it to fixture validation first, update the
affected rules (renames and defaults), then drop the oldest major one minor release later.

## Verification protocol (do this before writing any rule)
Training memory of provider schemas goes stale, and a wrong attribute name produces a rule that
never fires. So for every attribute a rule reads:

1. **Name and type, per supported major.** Use
   `bash ${CLAUDE_SKILL_DIR}/scripts/provider_schema.sh schema aws 6.67.0 aws_instance`. It
   prints attributes and nested blocks (required/optional/computed, sensitive, deprecated).
   Check the oldest supported major too.
2. **Default value, per supported major.** Schemas don't include defaults, so read the docs at that
   exact provider tag:
   `bash ${CLAUDE_SKILL_DIR}/scripts/provider_schema.sh docs azurerm 4.81.0 azurerm_storage_account allow_nested_items_to_be_public`.
   Record the default and its version in a comment beside `tf.value_or(...)`.
3. **Framework mapping.** Confirm the control ID and title on the official page (see
   frameworks.md) and cite that URL in `related_resources`. If you cannot verify it, leave the
   mapping out. A wrong mapping is worse than none in a compliance report.
4. **Write it down.** Note the versions checked in the PROGRESS entry, e.g. "verified against
   aws 5.100.0 / 6.67.0 docs".

The script needs network and terraform, and caches under `.cache/provider-schemas/` (gitignored).
It runs `terraform init` only on a config it generates, never on scanned code.

## How to read a catalog entry
```
### IACE-AWS-EC2-001 · EC2 instances must require IMDSv2   (P1 · high)
resources: aws_instance (+ aws_ec2_instance_metadata_defaults as account default)
check:     metadata_options[0].http_tokens == "required"; unset ⇒ account default if declared, else violation
defaults:  instance: AWS default (may allow IMDSv1); account resource: "no-preference"
mappings:  aws-securityhub EC2.8 (verified 2026-10-01)
fixtures:  fail: no metadata_options; http_tokens="optional" · pass: "required"; account default "required"
```
- **P1** = in the M6/M7 packs. **P2** = next wave. **P3** = backlog candidates.
- **check** is the precise rule logic. **defaults** lists what an *absent* attribute means, per major.
- Severity follows the rubric in `iace-rego-policies/references/metadata-schema.md`.

## Writing new entries
Add the entry to the catalog first (same format, unverified fields marked `(verify)`), then a
backlog task. Prefer controls that are:
- **statically decidable** from Terraform (not runtime state such as "unused credentials"),
- **high signal**: real risk, few legitimate exceptions,
- **unambiguous** about what "fixed" looks like (the AI remediation and humans both need that).

Out of scope for static rules: things only visible at runtime (key age, actual traffic, drift),
and organization-wide settings managed outside Terraform. Mention these in the rule's
`description` when they limit what the rule can prove.
