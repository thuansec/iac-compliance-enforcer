# iace backlog

Seed roadmap for iac-compliance-enforcer. Bootstrap copies this file to `docs/plan/BACKLOG.md`.
Format: `.claude/skills/iace-loop/references/backlog-format.md`. The plan is a walking skeleton:
the scanner works end to end early (M2) and then grows in depth.

## Loop settings
Permissions (push, pull requests, merge, live API calls) live in `.claude/loop-policy.json`.
- pause_at_milestone_end: yes
- max_attempts_per_task: 3

## Decisions needed
- D-03 · Where the policy-bundle signing key lives. iace loads central/org policy bundles only when
  their signature verifies, so whoever can sign decides what every consuming repository's scan
  enforces. The planned GitHub environment secret with required reviewers is not available here:
  GitHub Free offers environments only on public repositories. Options:
  (a) a repository Actions secret: free, but any workflow on any branch can read it, including
  workflows on the loop's feature branches;
  (b) AWS KMS (about US$1/month, one-time AWS setup by the owner): the key never leaves KMS, only
  the tag-triggered release workflow can sign (GitHub OIDC role limited to `policies-v*` tags), and
  CloudTrail logs every signature. `opa build` signs only with a local key file, so signing becomes
  a separate step (e.g. `cosign sign-blob --key awskms://…`) and T-0803 verifies that signature;
  (c) keyless Sigstore signing: no key to protect, but every signature is recorded in a public
  transparency log (repository and workflow names become public), so it fits only a public repo.
  Recommended: (b). Blocks: T-0802.

## M0 · Foundations — status: active
Goal: a buildable Go repository wired to GitHub, with pinned tools, gates, CI and project memory.

- [x] T-0001 · Bootstrap: wire the GitHub remote, create plan files and CLAUDE.md
  - skills: iace-loop
  - depends: —
  - accept:
    - `git remote get-url origin` is https://github.com/thuansec/iac-compliance-enforcer.git and main tracks origin/main
    - docs/plan/BACKLOG.md, docs/plan/PROGRESS.md and CLAUDE.md exist; .claude/ is committed; nothing pushed
  - attempts: 1
  - result: origin wired (main tracks origin/main at 6b37a48); BACKLOG, PROGRESS and CLAUDE.md created; .claude committed; nothing pushed
- [ ] T-0002 · Verify toolchain and pin each dev tool in its own module
  - skills: iace-go-standards, iace-quality-gates
  - depends: T-0001, T-0003
  - accept:
    - `go version` reports a current stable release, at least 1.24 (needed for tool directives); if Go is missing, the task is blocked needs-human with install commands
    - tools/<tool>/go.mod (with go.sum) pins each of golangci-lint v2, govulncheck, regal, actionlint and opa in its own module (D-07), with opa at exactly the version later used as the library
    - from the repository root, `go tool -modfile=tools/<tool>/go.mod <tool>` prints its version for each tool, and `go -C tools/<tool> mod tidy -diff` is clean for each module
    - `gates.sh full` passes and runs actionlint from tools/actionlint/go.mod
  - attempts: 1
- [ ] T-0003 · Scaffold the Go module and `iace version`
  - skills: iace-go-standards, iace-architecture, iace-testing
  - depends: T-0001
  - accept:
    - go.mod module path is github.com/thuansec/iac-compliance-enforcer; `go build ./...` passes
    - cmd/iace/main.go is a thin main; internal/cli holds a cobra root plus `version` (`--json`), with version/commit/date injected via ldflags (default "dev")
    - a testscript e2e test covers `iace version` and `iace version --json`
  - attempts: 0
- [ ] T-0004 · Add the Makefile, golangci-lint config and editor config
  - skills: iace-quality-gates, iace-go-standards
  - depends: T-0002, T-0003
  - accept:
    - the Makefile implements every target in the iace-quality-gates contract; `make ci` passes
    - .golangci.yml is adapted from the iace-go-standards asset; `golangci-lint config verify` passes
    - `gates.sh full` passes
  - attempts: 0
- [ ] T-0005 · Write the ADRs and docs skeleton
  - skills: iace-architecture
  - depends: T-0003
  - accept:
    - docs/adr/0001 (record decisions), 0002 (Go with embedded OPA v1 rego package), 0003 (static analysis by default; never execute Terraform from scanned repos)
    - README.md covers purpose, status, a quickstart placeholder and links; CONTRIBUTING.md covers the dev loop and gates
    - LICENSE holds the full Apache-2.0 text (D-01)
  - attempts: 0
- [ ] T-0006 · Extend the CI workflow with the full Go/OPA jobs
  - skills: iace-ci-cd, iace-security
  - depends: T-0004
  - accept:
    - .github/workflows/ci.yml (it already has `gates` + `ci-ok`) gains lint, test (race), policy-test, vuln and cross-build jobs via make, each listed in `ci-ok`'s `needs` so `ci-ok` stays the single required check
    - every action is pinned to a full commit SHA resolved with `gh api`, with a version comment; top-level `permissions: contents: read`; checkout uses `persist-credentials: false`
    - actionlint passes; .github/dependabot.yml covers gomod and github-actions
  - attempts: 0
- [ ] T-0007 · Write the security baseline documents
  - skills: iace-security
  - depends: T-0005
  - accept:
    - SECURITY.md (private vulnerability reporting), CODEOWNERS (@thuansec), docs/security/threat-model.md adapted from the iace-security reference
  - attempts: 0

## M1 · Terraform loading (static HCL) — status: planned
Goal: turn a directory of Terraform into the normalized input document v1, with exact source
locations and without executing anything.

- [ ] T-0101 · Define the input document v1 types and JSON Schema
  - skills: iace-architecture, iace-terraform-parsing, iace-testing
  - depends: T-0004
  - accept:
    - internal/model types match iace-architecture/references/input-document.md; schemas/input.v1.json validates the reference example in a test
    - ADR 0004 records the input contract
  - attempts: 0
- [ ] T-0102 · Discover root modules safely
  - skills: iace-terraform-parsing, iace-security, iace-testing
  - depends: T-0101
  - accept:
    - skips .terraform, .git and hidden dirs; never follows symlinks outside the scan root; enforces the file-size (5 MiB) and file-count limits with clear errors
    - separates root modules from local child modules; tests cover symlink escape, oversized files and nested roots
  - attempts: 0
- [ ] T-0103 · Parse HCL and JSON syntax files into raw blocks with ranges
  - skills: iace-terraform-parsing, iace-testing
  - depends: T-0102
  - accept:
    - .tf and .tf.json are parsed with hclparse; diagnostics become structured warnings/errors with file:line
    - override files are handled or reported as warnings; FuzzParse has a seed corpus and runs 60s without a panic
  - attempts: 0
- [ ] T-0104 · Evaluate variables and locals
  - skills: iace-terraform-parsing, iace-testing
  - depends: T-0103
  - accept:
    - defaults, terraform.tfvars, *.auto.tfvars (lexical order), --var-file and --var are applied with Terraform precedence; sensitive variables are tracked
    - locals are evaluated in dependency order; a cycle yields unknown plus a warning; unknown paths are recorded
  - attempts: 0
- [ ] T-0105 · Evaluate expressions with a curated function set
  - skills: iace-terraform-parsing, iace-security
  - depends: T-0104
  - accept:
    - the function table is documented in the reference; unsupported functions yield unknown, never an error
    - file() and templatefile() are confined to the module directory with a size limit; tests cover escape attempts
  - attempts: 0
- [ ] T-0106 · Expand count, for_each and dynamic blocks
  - skills: iace-terraform-parsing, iace-testing
  - depends: T-0105
  - accept:
    - instance addresses look like `type.name[0]` and `type.name["key"]`; unknown count/for_each yields one placeholder instance marked unknown
    - the expansion cap (10,000 by default) produces a warning; dynamic blocks expand
  - attempts: 0
- [ ] T-0107 · Resolve local and pre-downloaded modules
  - skills: iace-terraform-parsing, iace-security
  - depends: T-0106
  - accept:
    - local sources resolve only inside the scan root (an escape leaves the module unresolved with a warning); inputs and outputs flow; depth limit 32; cycles detected
    - remote modules resolve only via .terraform/modules/modules.json; unresolved modules are reported as coverage gaps
  - attempts: 0
- [ ] T-0108 · Extract references and provider versions
  - skills: iace-terraform-parsing
  - depends: T-0107
  - accept:
    - per-attribute references to resource addresses; provider local names are mapped to source addresses, including aliases
    - .terraform.lock.hcl versions populate provider_versions; tests cover each
  - attempts: 0
- [ ] T-0109 · Normalize into the input document with golden tests and `iace inspect`
  - skills: iace-terraform-parsing, iace-testing, iace-architecture
  - depends: T-0108
  - accept:
    - `iace inspect <path> --json` prints the input document; output is byte-identical across runs
    - golden tests cover testdata/terraform/e2e/*; the 1k-resource benchmark result is recorded in PROGRESS
  - attempts: 0

## M2 · Policy engine and walking skeleton — status: planned
Goal: `iace scan <path>` evaluates embedded Rego with OPA and prints findings; every error fails closed.

- [ ] T-0201 · Create the policy library skeleton
  - skills: iace-rego-policies, iace-opa-engine
  - depends: T-0109
  - accept:
    - policies/ is seeded from iace-rego-policies `assets/policies/` (package-mirroring layout); policies/embed.go exposes it via go:embed
    - `make capabilities` generates policies/capabilities.json from the pinned OPA, minus the denylist, and a test asserts the denylisted builtins are absent
    - .regal/config.yaml copied from `assets/regal-config.yaml`; `regal lint policies` is clean; `make policy-check policy-test` passes with at least 90% coverage
  - attempts: 0
- [ ] T-0202 · Load modules and validate rule metadata (fail closed)
  - skills: iace-opa-engine, iace-rego-policies
  - depends: T-0201
  - accept:
    - modules parse with annotations; metadata is validated against iace-rego-policies/references/metadata-schema.md
    - a duplicate rule ID, missing required metadata or a missing `deny` rule each produce a load error naming the file; there is a test per case
  - attempts: 0
- [ ] T-0203 · Compile and evaluate with restricted capabilities
  - skills: iace-opa-engine, iace-go-standards
  - depends: T-0202
  - accept:
    - one prepared query, Rego v1, strict mode, StrictBuiltinErrors, per-evaluation timeout, input converted once via EvalParsedInput
    - root modules are evaluated concurrently with a bounded errgroup; there is an engine benchmark
  - attempts: 0
- [ ] T-0204 · Decode violations into findings
  - skills: iace-opa-engine, iace-architecture
  - depends: T-0203
  - accept:
    - strict decoding; the violation's address must exist in the input; location comes from the attribute range when the path is known, otherwise the block range
    - fingerprints are stable across runs and line shifts; tests cover each
  - attempts: 0
- [ ] T-0205 · Ship the first rules end to end, with the fixture harness
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0204
  - accept:
    - IACE-AWS-EC2-001 (from the asset), IACE-AWS-S3-001 and IACE-AZURE-STORAGE-001, each with Rego tests and pass/fail Terraform fixtures
    - the fixture harness fails if any rule lacks a pass or a fail fixture
  - attempts: 0
- [ ] T-0206 · Implement `iace scan` with text output and exit codes
  - skills: iace-architecture, iace-reporting, iace-testing
  - depends: T-0205
  - accept:
    - flags follow iace-architecture/references/findings-and-cli.md; exit 0 when clean, 1 for blocking findings, 2 for errors
    - testscript covers a clean repo, a failing repo, a broken policy and a Terraform parse error
  - attempts: 0
- [ ] T-0207 · Implement `iace rules list` and `iace rules show <id>`
  - skills: iace-architecture, iace-opa-engine
  - depends: T-0206
  - accept:
    - list shows ID, severity, CSP, title and source; show prints the full metadata and remediation; testscript covers both
  - attempts: 0

## M3 · Reports — status: planned
Goal: machine- and human-readable outputs that CI systems and GitHub understand.

- [ ] T-0301 · JSON report v1 with schema and golden tests
  - skills: iace-reporting, iace-architecture
  - depends: T-0207
  - accept:
    - schemas/findings.v1.json; the report includes tool version, policy sources, summary, findings, warnings and coverage gaps; golden test; deterministic order
  - attempts: 0
- [ ] T-0302 · SARIF 2.1.0 output for GitHub code scanning
  - skills: iace-reporting
  - depends: T-0301
  - accept:
    - follows iace-reporting/references/sarif.md (security-severity, tags, help, relative URIs, automationDetails)
    - validates against the vendored SARIF 2.1.0 schema in a test; golden test
  - attempts: 0
- [ ] T-0303 · JUnit XML output
  - skills: iace-reporting
  - depends: T-0301
  - accept:
    - one testcase per rule × resource, failures for open findings; golden test; well-formed XML
  - attempts: 0
- [ ] T-0304 · Markdown summary and GitHub annotations output
  - skills: iace-reporting, iace-ci-cd
  - depends: T-0301
  - accept:
    - Markdown stays under 1 MiB with truncation notice; `--output github` emits ::error/::warning lines with file/line; golden tests
  - attempts: 0
- [ ] T-0305 · Multiple outputs per run, with atomic writes and TTY handling
  - skills: iace-reporting, iace-go-standards
  - depends: T-0302
  - accept:
    - `-o text -o sarif=results.sarif -o json=out.json` in one run; files are written atomically; NO_COLOR and non-TTY are respected; testscript
  - attempts: 0
- [ ] T-0306 · Report coverage gaps in every format
  - skills: iace-reporting, iace-terraform-parsing
  - depends: T-0305
  - accept:
    - unparsed files, unresolved modules and unknown-valued checks appear in all formats; `--fail-on-gaps` exits 2 when gaps exist
  - attempts: 0

## M4 · Repo policy config — status: planned
Goal: each scanned repository controls policy selection, thresholds and accountable exceptions via `.iace.yaml`.

- [ ] T-0401 · `.iace.yaml` v1 schema, strict loader and discovery
  - skills: iace-repo-policy, iace-security
  - depends: T-0306
  - accept:
    - schemas/config.v1.json; unknown keys are errors; errors cite file:line
    - discovery order: `--config`, the scan root, the git toplevel; tests
  - attempts: 0
- [ ] T-0402 · `iace init` scaffolds a commented config
  - skills: iace-repo-policy
  - depends: T-0401
  - accept:
    - detects CSPs from the providers in use; writes .iace.yaml without overwriting an existing file (unless --force); testscript
  - attempts: 0
- [ ] T-0403 · Policy selection
  - skills: iace-repo-policy, iace-opa-engine
  - depends: T-0401
  - accept:
    - csps, frameworks, min_severity and disabled_rules (with required owner and reason) select rules; disabled rules are listed in reports; tests
  - attempts: 0
- [ ] T-0404 · Severity thresholds and exit codes
  - skills: iace-repo-policy, iace-reporting
  - depends: T-0403
  - accept:
    - `fail_on` (default high) decides exit 1; `--fail-on` overrides; the summary shows which findings blocked
  - attempts: 0
- [ ] T-0405 · Exceptions with owner, reason and expiry
  - skills: iace-repo-policy, iace-reporting, iace-testing
  - depends: T-0404
  - accept:
    - matching by rule IDs, resource address globs and optional path globs; owner, reason (≥ 15 characters) and expires (ISO date ≤ max_expiry_days) are required
    - expired exceptions stop applying and produce a warning; expiring within 14 days warns; stale exceptions warn; SARIF suppressions are populated; tests per case with an injected clock
  - attempts: 0
- [ ] T-0406 · Rule parameters (optional)
  - skills: iace-repo-policy, iace-opa-engine, iace-rego-policies
  - depends: T-0405
  - accept:
    - `rule_params` is validated against each rule's declared params schema and exposed as data.iace.params[<id>]; a required-tags rule demonstrates it
  - attempts: 0
- [ ] T-0407 · Org baseline config: repositories can only tighten
  - skills: iace-repo-policy, iace-security
  - depends: T-0405
  - accept:
    - `--org-config` sets mandatory rules, a minimum fail_on, max exception days and non-exceptionable rules
    - a repo config that tries to loosen any of them is an error; tests
  - attempts: 0

## M5 · PR/CI enforcement — status: planned
Goal: scans run on pull requests, results reach GitHub code scanning, and merging requires a passing check.

- [ ] T-0501 · Composite GitHub Action
  - skills: iace-ci-cd, iace-security
  - depends: T-0407
  - accept:
    - action.yml takes the inputs in iace-ci-cd/references/consumer-workflow.md; build-from-source mode now, release-binary mode with checksum verification ready for M11
    - SARIF is uploaded and the summary written before the job fails on the scan result
  - attempts: 0
- [ ] T-0502 · Example consumer workflow and docs
  - skills: iace-ci-cd
  - depends: T-0501
  - accept:
    - examples/github/iace.yml: pull_request plus push to main, least-privilege permissions, upload-sarif pinned by SHA with category; docs/ci/github.md
  - attempts: 0
- [ ] T-0503 · Self-test workflow running the action from this repo
  - skills: iace-ci-cd, iace-testing
  - depends: T-0502
  - accept:
    - a workflow with `uses: ./` against testdata/e2e asserts the expected exit code and SARIF content; actionlint passes
  - attempts: 0
- [ ] T-0504 · Required-check setup guide
  - skills: iace-ci-cd
  - depends: T-0502
  - accept:
    - docs/ci/required-checks.md gives ruleset JSON and the `gh api` commands (documented, not executed)
    - covers private repos without code scanning (annotations plus a required status check)
  - attempts: 0
- [ ] T-0505 · Azure DevOps pipeline template (optional)
  - skills: iace-ci-cd, iace-reporting
  - depends: T-0502
  - accept:
    - examples/azure-pipelines/iace.yml publishes JUnit results and the SARIF artifact; docs
  - attempts: 0

## M6 · AWS policy pack — status: planned
Goal: the P1 AWS controls in iace-cloud-controls/references/aws.md, each with tests, fixtures and verified mappings.
Standard acceptance for every rule task: the Rego rule follows iace-rego-policies, with ≥ 90% coverage; there are pass/fail fixtures that are valid for aws provider 5.x and 6.x; attribute names and defaults are verified with provider_schema.sh or the registry docs; framework mappings are verified against the official control reference; rule docs are regenerated.

- [ ] T-0601 · IACE-AWS-S3-002 · No public bucket ACLs
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance (see the milestone goal)
  - attempts: 0
- [ ] T-0602 · IACE-AWS-VPC-001 · No internet ingress to admin ports
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers inline ingress, aws_security_group_rule and aws_vpc_security_group_ingress_rule, IPv4 and IPv6, port ranges and protocol -1
  - attempts: 0
- [ ] T-0603 · IACE-AWS-VPC-002 · No unrestricted ingress on all ports
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0602
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0604 · IACE-AWS-EC2-002 · Encrypted EBS volumes
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers aws_ebs_volume and instance root/ebs block devices, and honours aws_ebs_encryption_by_default in the same configuration
  - attempts: 0
- [ ] T-0605 · IACE-AWS-RDS-001 · Encrypted RDS storage
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers aws_db_instance and aws_rds_cluster
  - attempts: 0
- [ ] T-0606 · IACE-AWS-RDS-002 · RDS not publicly accessible
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0607 · IACE-AWS-IAM-001 · No full-admin IAM policies
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers JSON strings (heredoc and jsonencode) and aws_iam_policy_document data sources, with Action/Resource as string or list
  - attempts: 0
- [ ] T-0608 · IACE-AWS-KMS-001 · KMS key rotation
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; asymmetric and HMAC keys are exempt
  - attempts: 0
- [ ] T-0609 · IACE-AWS-CT-001 · CloudTrail log file validation
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0610 · IACE-AWS-EKS-001 · EKS API endpoint not open to the internet
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; fails when endpoint_public_access is true (the default) and public_access_cidrs includes 0.0.0.0/0 (the default)
  - attempts: 0
- [ ] T-0611 · IACE-AWS-ELB-001 · HTTPS listeners on load balancers
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; an HTTP listener whose default action redirects to HTTPS passes
  - attempts: 0
- [ ] T-0612 · IACE-GEN-SECRETS-001 · No hardcoded secrets in sensitive arguments
  - skills: iace-rego-policies, iace-cloud-controls, iace-security
  - depends: T-0407
  - accept:
    - standard rule acceptance for both AWS and Azure arguments; messages never contain the value; a test asserts no fixture secret appears in any output format
  - attempts: 0
- [ ] T-0699 · Workflow that validates fixtures against provider schemas
  - skills: iace-ci-cd, iace-cloud-controls
  - depends: T-0612
  - accept:
    - a nightly/manual workflow runs `terraform validate` on every fixture for aws 5.x and 6.x (and azurerm 4.x and 5.x once M7 lands); it is not part of PR CI because it needs network access
  - attempts: 0

## M7 · Azure policy pack — status: planned
Goal: the P1 Azure controls in iace-cloud-controls/references/azure.md. Standard rule acceptance
as in M6, valid for azurerm 4.x and 5.x, with renamed attributes and changed defaults handled.

- [ ] T-0701 · IACE-AZURE-STORAGE-002 · HTTPS-only storage accounts
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0702 · IACE-AZURE-STORAGE-003 · No anonymous blob access
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; the default differs by provider major (4.x vs 5.x) and both are tested; covers container_access_type
  - attempts: 0
- [ ] T-0703 · IACE-AZURE-KV-001 · Key Vault purge protection
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0704 · IACE-AZURE-KV-002 · Key Vault network access restricted
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0705 · IACE-AZURE-NET-001 · No internet SSH/RDP in NSGs
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers inline security_rule and azurerm_network_security_rule, singular and plural prefix/port fields, and the sources *, 0.0.0.0/0, Internet and Any
  - attempts: 0
- [ ] T-0706 · IACE-AZURE-NET-002 · No internet ingress on all ports in NSGs
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0705
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0707 · IACE-AZURE-SQL-001 · SQL Server minimum TLS 1.2
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0708 · IACE-AZURE-SQL-002 · SQL Server public network access disabled
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0709 · IACE-AZURE-SQL-003 · No allow-all SQL firewall rules
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0710 · IACE-AZURE-AKS-001 · AKS API server access restricted
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; a private cluster or non-empty authorized_ip_ranges passes
  - attempts: 0
- [ ] T-0711 · IACE-AZURE-APP-001 · Web apps HTTPS only
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance; covers linux and windows web apps and function apps
  - attempts: 0
- [ ] T-0712 · IACE-AZURE-APP-002 · Web apps minimum TLS 1.2
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0711
  - accept:
    - standard rule acceptance
  - attempts: 0
- [ ] T-0713 · IACE-AZURE-VM-001 · Linux VMs disable password authentication
  - skills: iace-rego-policies, iace-cloud-controls, iace-testing
  - depends: T-0407
  - accept:
    - standard rule acceptance
  - attempts: 0

## M8 · Central and external policy sources — status: planned
Goal: repositories pin a central or org policy bundle to an exact version, and iace verifies it
before loading it alongside the built-in policies.

- [ ] T-0801 · Policy source abstraction with namespace isolation
  - skills: iace-repo-policy, iace-opa-engine, iace-security
  - depends: T-0713
  - accept:
    - builtin and bundle sources load as OPA bundles with manifest roots; overlapping roots or duplicate rule IDs are errors naming both sources; tests
  - attempts: 0
- [ ] T-0802 · Build and sign policy bundles from this repository
  - skills: iace-repo-policy, iace-ci-cd
  - depends: T-0801
  - accept:
    - `make policy-bundle` builds a signed bundle (ES256) plus sha256; the release workflow publishes both; key custody follows D-03; docs/policies/publishing.md
  - attempts: 0
- [ ] T-0803 · Load pinned, verified bundles
  - skills: iace-repo-policy, iace-security
  - depends: T-0802
  - accept:
    - local and HTTPS bundles: the sha256 pin is required and must match; the signature is verified against the trust store (embedded official keys plus CI-provided keys)
    - size and time limits; the token is sent only to allowlisted hosts and never across redirects; tests cover tampering, a wrong key, a wrong digest and an oversized bundle
  - attempts: 0
- [ ] T-0804 · Content-addressed cache and `--offline`
  - skills: iace-repo-policy
  - depends: T-0803
  - accept:
    - the cache is keyed by sha256 and re-verified on every load; `--offline` fails clearly when a bundle is missing; tests
  - attempts: 0
- [ ] T-0805 · Policy provenance in reports
  - skills: iace-reporting, iace-repo-policy
  - depends: T-0803
  - accept:
    - every finding and the report header name the policy source, its version and its digest in all formats
  - attempts: 0
- [ ] T-0806 · `iace policy test|check|build` for policy authors
  - skills: iace-opa-engine, iace-rego-policies
  - depends: T-0803
  - accept:
    - authors in other repositories can test against the iace lib and capabilities without installing opa; docs/policies/authoring.md
  - attempts: 0

## M9 · Plan JSON input — status: planned
Goal: higher-fidelity scans from `terraform show -json` output produced by trusted pipelines.

- [ ] T-0901 · Ingest plan JSON
  - skills: iace-terraform-parsing
  - depends: T-0806
  - accept:
    - `iace scan --plan plan.json` reads it via hashicorp/terraform-json; unsupported format_version majors are rejected
  - attempts: 0
- [ ] T-0902 · Map plan values to the input document
  - skills: iace-terraform-parsing, iace-architecture
  - depends: T-0901
  - accept:
    - after values, after_unknown and after_sensitive are mapped; deletes are excluded; references come from configuration; tests
  - attempts: 0
- [ ] T-0903 · Source locations for plan scans
  - skills: iace-terraform-parsing, iace-reporting
  - depends: T-0902
  - accept:
    - `--source <dir>` maps config addresses to block ranges; missing locations degrade to the module directory with a warning
  - attempts: 0
- [ ] T-0904 · Parity tests between HCL and plan modes
  - skills: iace-testing, iace-terraform-parsing
  - depends: T-0903
  - accept:
    - for fixtures with fully known values, both modes produce identical findings (golden plan JSON is committed, never generated in tests)
  - attempts: 0

## M10 · AI fix suggestions — status: planned
Goal: opt-in AI suggestions for violations, verified by re-scanning before anyone sees them.

- [ ] T-1001 · Suggester interface, config and disclosure
  - skills: iace-ai-remediation, iace-architecture
  - depends: T-0904
  - accept:
    - `ai:` config block plus flags; off by default; enabling prints the data disclosure; noop and fake implementations; tests
  - attempts: 0
- [ ] T-1002 · Redaction and context minimization
  - skills: iace-ai-remediation, iace-security
  - depends: T-1001
  - accept:
    - sensitive attributes, sensitive variables and secret patterns are replaced with placeholders; only the offending blocks and their direct dependencies are sent; tests with secret fixtures prove nothing leaks
  - attempts: 0
- [ ] T-1003 · Versioned prompt and output schema
  - skills: iace-ai-remediation
  - depends: T-1002
  - accept:
    - the prompt follows references/prompt-contract.md; golden prompt tests; the structured-output JSON schema lives in schemas/ai-fix.v1.json
  - attempts: 0
- [ ] T-1004 · Bedrock provider
  - skills: iace-ai-remediation, claude-api
  - depends: T-1003
  - accept:
    - uses anthropic-sdk-go's Bedrock Mantle client with default model `anthropic.claude-opus-5-5` and configurable effort; timeouts, retries, refusal handling and prompt caching
    - region and credentials come only from the AWS environment (never `.iace.yaml`) and are read only when AI is enabled; the disclosure names provider, region and model
    - all tests use httptest with obviously fake credentials; there are no live calls unless `live_api_calls` is true in .claude/loop-policy.json
  - attempts: 0
- [ ] T-1005 · Fix validator
  - skills: iace-ai-remediation, iace-security, iace-opa-engine
  - depends: T-1004
  - accept:
    - each fix is applied in memory, re-parsed and checked for dangerous constructs, then the scan is re-run; only fixes that resolve the finding without adding new ones are "verified"; tests cover malicious outputs
  - attempts: 0
- [ ] T-1006 · Output integration and `iace fix`
  - skills: iace-ai-remediation, iace-reporting
  - depends: T-1005
  - accept:
    - text diff, JSON, Markdown and SARIF fixes; `iace fix --ai --write` requires a clean git tree (or --force) and writes atomically; testscript with the fake provider
  - attempts: 0
- [ ] T-1007 · Suggestion cache, cost controls and usage summary
  - skills: iace-ai-remediation
  - depends: T-1006
  - accept:
    - a 0600 cache keyed by prompt version, model and redacted context; max_findings, concurrency and a token budget; token usage in the summary
  - attempts: 0
- [x] T-1008 · Bedrock and Vertex providers (optional)
  - skills: iace-ai-remediation, claude-api
  - depends: T-1007
  - accept:
    - provider selection via config; same validation pipeline; httptest-based tests
  - attempts: 0
  - result: superseded by T-1004 (D-05: Amazon Bedrock is the only approved provider; Vertex is not approved)
- [ ] T-1009 · Opt-in eval harness
  - skills: iace-ai-remediation, iace-testing
  - depends: T-1007
  - accept:
    - testdata/ai-evals with a runner that reports verified-fix rate, new-finding rate and tokens; it runs only with explicit opt-in and records a baseline in PROGRESS
  - attempts: 0

## M11 · Release and hardening — status: planned
Goal: signed, reproducible releases with SBOM and provenance, plus a hardening pass.

- [ ] T-1101 · GoReleaser, SBOM, signing and provenance
  - skills: iace-ci-cd, iace-security
  - depends: T-1009
  - accept:
    - `goreleaser release --snapshot --clean` works locally; the release workflow (tag-triggered) signs with cosign keyless and attests build provenance; checksums and SBOM are published
  - attempts: 0
- [ ] T-1102 · Fuzzing campaign and resource-limit tests
  - skills: iace-testing, iace-security
  - depends: T-1101
  - accept:
    - every fuzz target runs 10 minutes without a crash; tests cover huge files, deep nesting, bundle bombs and expansion caps
  - attempts: 0
- [ ] T-1103 · Performance budget
  - skills: iace-opa-engine, iace-terraform-parsing, iace-testing
  - depends: T-1101
  - accept:
    - a 5k-resource synthetic repo scans in under 10s and under 1 GiB on a 4-core runner; the profile is recorded in PROGRESS
  - attempts: 0
- [ ] T-1104 · Generated rule reference and user docs
  - skills: iace-rego-policies, iace-reporting
  - depends: T-1101
  - accept:
    - docs/rules/*.md are generated from metadata (CI checks they are current); user guide; policy authoring guide
  - attempts: 0
- [ ] T-1105 · Threat model review and security sign-off
  - skills: iace-security
  - depends: T-1102
  - accept:
    - the threat model is updated to match the code; every mitigation maps to a test; the checklist results are recorded
  - attempts: 0
- [ ] T-1106 · v0.1.0 release checklist
  - skills: iace-ci-cd
  - depends: T-1105
  - accept:
    - blocked needs-human: the human tags and publishes; the loop prepares the changelog and release notes
  - attempts: 0
