# iac-compliance-enforcer (iace)

iace checks Terraform for security and compliance misconfigurations in AWS and Azure before they
merge. It analyzes Terraform statically, so it never runs Terraform, providers or modules from
the code it scans. It evaluates Rego policies with an embedded Open Policy Agent, maps findings
to frameworks such as the CIS Foundations Benchmarks, and is built to gate pull requests: text,
JSON, SARIF, JUnit and Markdown reports, and exit codes CI can act on.

## Status
Early development. iace loads Terraform without executing it and prints what its policies will
evaluate (`iace inspect`); scanning with policies arrives with milestone M2. Plans and history:
[backlog](docs/plan/BACKLOG.md) and [progress log](docs/plan/PROGRESS.md).

## Quickstart
Scanning isn't available yet. Once M2 lands it will look like this:

```bash
iace scan ./infra          # exit 0: clean, 1: blocking findings, 2: could not scan
```

Today you can inspect how iace reads a configuration (Go 1.27 or later):

```bash
go run ./cmd/iace inspect ./infra          # one summary per root module, with coverage gaps
go run ./cmd/iace inspect ./infra --json   # the input documents policies evaluate, secrets redacted
go run ./cmd/iace version
```

`inspect` exits 2 when a file cannot be parsed as Terraform would parse it. Remote modules
resolve only with `--trust-module-manifest` (or `IACE_TRUST_MODULE_MANIFEST=true`), for a pipeline
that ran `terraform init` itself after removing any committed `.terraform`.

## Documentation
- [Contributing](CONTRIBUTING.md): the development loop, commands and quality gates
- [Architecture decisions](docs/adr/)
- [Branch, CI and merge workflow](docs/ci/branch-workflow.md)
- [Security notes](docs/security/)

## Security
Please report vulnerabilities privately through GitHub's private vulnerability reporting (the
repository's **Security** tab, then **Report a vulnerability**), not in public issues. See
[SECURITY.md](SECURITY.md) for what to include and what is in scope.

## License
[Apache License 2.0](LICENSE)
