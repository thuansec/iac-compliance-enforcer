# SARIF 2.1.0 for GitHub code scanning

The requirements below were checked against GitHub's "SARIF support for code scanning" docs on
2026-10-01.

## Skeleton
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {
      "name": "iace",
      "informationUri": "https://github.com/thuansec/iac-compliance-enforcer",
      "semanticVersion": "0.3.0",
      "rules": [ /* one per rule that produced a finding, or all loaded rules */ ]
    }},
    "automationDetails": {"id": "iace/infra-prod/"},
    "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
    "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": []}],
    "results": [ /* findings */ ]
  }]
}
```
For the `%SRCROOT%` placeholder, either omit `originalUriBaseIds` and use repo-relative URIs, or
set it to the checkout root. GitHub needs paths **relative to the repository root**.

## Rule object
```json
{
  "id": "IACE-AWS-EC2-001",
  "name": "Ec2InstancesMustRequireImdsv2",
  "shortDescription": {"text": "EC2 instances must require IMDSv2"},
  "fullDescription": {"text": "<metadata description>"},
  "helpUri": "https://github.com/thuansec/iac-compliance-enforcer/blob/main/docs/rules/IACE-AWS-EC2-001.md",
  "help": {"text": "<remediation>", "markdown": "**Remediation:** <remediation>\n\n[AWS docs](<related_resources[0]>)"},
  "defaultConfiguration": {"level": "error"},
  "properties": {
    "security-severity": "8.0",
    "precision": "high",
    "tags": ["security", "terraform", "aws", "ec2", "aws-securityhub/EC2.8"]
  }
}
```
- `security-severity` must be a numeric **string** in 0.1–10.0. GitHub maps >9.0 to critical,
  7.0–8.9 to high, 4.0–6.9 to medium and 0.1–3.9 to low. 0.0 or out of range means no security
  severity. iace mapping:

  | iace severity | security-severity | level |
  |---|---|---|
  | critical | `"9.5"` | `error` |
  | high | `"8.0"` | `error` |
  | medium | `"5.5"` | `warning` |
  | low | `"3.0"` | `note` |
  | info | omit the property | `note` |

- Include `"security"` in `tags` so GitHub treats results as security alerts. Keep tags at 20 or
  fewer (GitHub displays 10).

## Result object
```json
{
  "ruleId": "IACE-AWS-EC2-001",
  "ruleIndex": 0,
  "level": "error",
  "message": {"text": "aws_instance.web allows IMDSv1: set metadata_options.http_tokens to \"required\""},
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "infra/prod/compute.tf"},
      "region": {"startLine": 9, "startColumn": 5, "endLine": 9, "endColumn": 29}
    },
    "logicalLocations": [{"fullyQualifiedName": "aws_instance.web", "kind": "resource"}]
  }],
  "partialFingerprints": {"iaceFinding/v1": "<finding.fingerprint>"},
  "properties": {"policySource": "builtin@0.3.0"}
}
```
- GitHub only uses `partialFingerprints.primaryLocationLineHash` for alert tracking, and the
  upload-sarif action computes it when it is absent. Our own `iaceFinding/v1` key is for other
  consumers and baselines, so keep it.
- **Excepted findings**: include them with
  `"suppressions": [{"kind": "external", "status": "accepted", "justification": "<reason> (owner <owner>, expires <date>, EXC-…)"}]`.
  Verify how GitHub currently renders suppressed results, then document it in docs/ci/github.md.
- **AI fixes** (M10): only for *verified* suggestions, as
  `"fixes": [{"description": {"text": "…"}, "artifactChanges": [{"artifactLocation": {"uri": "…"}, "replacements": [{"deletedRegion": {…}, "insertedContent": {"text": "…"}}]}]}]`.
  GitHub may not render them, but other tools do.
- Findings without a file location (rare: plan mode without `--source`) point at the
  root-module directory's main file at line 1, and say so in the message.

## Multiple uploads (monorepos)
Set a distinct `automationDetails.id` per scanned root (e.g. `iace/<root-path>/`), or one run
for the whole repo. Use the same value as the `category` input of `upload-sarif`. Without it,
uploads for different roots overwrite each other.

## Limits (GitHub)
10 MB gzip-compressed per file; 25,000 results per run (top 5,000 shown); 20 runs per file;
1,000 locations per result (100 shown); 25,000 rules per run. If results would exceed the cap,
keep the highest severities, add a `toolExecutionNotifications` entry stating the truncation,
and exit as usual (truncation never changes the exit code).

## Validation in tests
Vendor the SARIF 2.1.0 JSON schema under `internal/report/sarif/testdata/` and validate every
golden output with `santhosh-tekuri/jsonschema/v6`. Also assert that every `ruleIndex` points at
a matching `rules[].id`.
