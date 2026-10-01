# Framework keys and mapping policy

`custom.frameworks` in rule metadata maps a framework key to control IDs. Reports (JSON, SARIF
tags, Markdown) and policy selection (`.iace.yaml` `frameworks:`) use these keys.

| key | framework | ID format | where to verify |
|---|---|---|---|
| `aws-securityhub` | AWS Security Hub control IDs. One ID scheme shared by the FSBP, CIS, PCI and NIST standards inside Security Hub. | `S3.1`, `EC2.8` | https://docs.aws.amazon.com/securityhub/latest/userguide/<service>-controls.html (each control lists the standards it belongs to) |
| `mcsb` | Microsoft cloud security benchmark | `NS-2`, `DP-3` | https://learn.microsoft.com/security/benchmark/azure/ (domain pages: network security, data protection, …) |
| `cis-aws@<version>` | CIS Amazon Web Services Foundations Benchmark | `2.1.4` | the CIS PDF for that version (needs a CIS account; decision D-06) |
| `cis-azure@<version>` | CIS Microsoft Azure Foundations Benchmark | `3.1.1` | the CIS PDF for that version (decision D-06) |
| `nist-800-53r5` | NIST SP 800-53 Rev. 5 | `SC-8`, `SC-28`, `AC-3` | https://csrc.nist.gov/projects/cprt/catalog |

## Mapping policy
1. **Only verified mappings ship.** Before adding a mapping, open the official control page,
   confirm the ID and that its intent matches the rule, and add the page URL to `related_resources`.
2. **CIS keys always carry the benchmark version** (`cis-aws@5.0.0`), because CIS renumbers
   between versions. Map only to versions that decision D-06 approved.
3. **Map to the most specific control.** If a rule covers only part of a control (e.g. port 22 of
   "remote administration ports"), the mapping is still valid. Say so in `description`.
4. **NIST mappings must be justified** (e.g. encryption at rest → SC-28, in transit → SC-8, least
   privilege → AC-6). They are broad, so add them only when a team requests NIST reporting.
5. A rule's mappings may change without changing its ID. Note the change in the changelog.

## Using frameworks in config
`.iace.yaml` `policies.frameworks: [aws-securityhub, cis-aws@5.0.0]` evaluates only rules mapped
to at least one listed framework. Reports group findings by framework control in the JSON
`frameworks` section and as SARIF tags (`aws-securityhub/S3.1`).
