# Security policy

## Reporting a vulnerability
Please report security issues privately through GitHub's private vulnerability reporting: open
this repository's **Security** tab and choose **Report a vulnerability**. Don't open a public
issue or pull request for a suspected vulnerability.

Include as much as you can:
- the affected version (`iace version --json`) or commit;
- a minimal input that triggers it (Terraform directory, `.iace.yaml` or policy bundle), with
  obviously fake values, never real secrets;
- what you expected, what happened, and the impact you see.

The conversation continues in the private advisory, where we agree on a fix and on when to
disclose. You'll be credited in the advisory unless you'd rather not be.

## Supported versions
iace has no release yet. Until 1.0, security fixes go to `main` and the latest release only.

## Scope
In scope: the iace CLI and its built-in policies, the GitHub Action, policy bundles published
from this repository, release artifacts, and this repository's CI workflows. Because iace scans
untrusted pull requests ([threat model](docs/security/threat-model.md)), these matter most:
- anything that makes iace execute code from scanned content, or read or write outside the scan root;
- a misconfiguration reported as compliant because of a parsing, evaluation or exception bug;
- secret values reaching reports, logs, caches or AI prompts;
- ways around policy-bundle verification;
- crafted input that hangs or crashes iace instead of failing cleanly.

Out of scope: vulnerabilities in the Terraform code you scan (finding those is iace's job), in
Terraform providers, or in GitHub itself. Requests for more checks are welcome as regular issues.
