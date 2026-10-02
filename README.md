# iac-compliance-enforcer (iace)

iace checks Terraform for security and compliance misconfigurations in AWS and Azure before they
merge. It analyzes Terraform statically, so it never runs Terraform, providers or modules from
the code it scans. It evaluates Rego policies with an embedded Open Policy Agent, maps findings
to frameworks such as the CIS Foundations Benchmarks, and is built to gate pull requests: text,
JSON, SARIF, JUnit and Markdown reports, and exit codes CI can act on.

## Status
Early development. The repository has the Go module, the pinned tools, the quality gates, CI and
`iace version`. Scanning arrives with milestone M2. Plans and history:
[backlog](docs/plan/BACKLOG.md) and [progress log](docs/plan/PROGRESS.md).

## Quickstart
Scanning isn't available yet. Once M2 lands it will look like this:

```bash
iace scan ./infra          # exit 0: clean, 1: blocking findings, 2: could not scan
```

Today you can build the CLI and print its version (Go 1.27 or later):

```bash
go run ./cmd/iace version
go run ./cmd/iace version --json
```

## Documentation
- [Contributing](CONTRIBUTING.md): the development loop, commands and quality gates
- [Architecture decisions](docs/adr/)
- [Branch, CI and merge workflow](docs/ci/branch-workflow.md)
- [Security notes](docs/security/)

## Security
Please report vulnerabilities privately through GitHub's private vulnerability reporting (the
repository's **Security** tab, then **Report a vulnerability**), not in public issues.

## License
[Apache License 2.0](LICENSE)
