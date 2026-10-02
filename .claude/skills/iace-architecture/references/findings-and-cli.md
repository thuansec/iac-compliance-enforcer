# Findings, CLI and exit codes

## Finding v1
Built by `internal/engine` (from a violation plus rule metadata plus source map), then updated by
`internal/exceptions` and `internal/remediation`. Reporters only read findings.

| field | type | notes |
|---|---|---|
| `rule_id` | string | `IACE-AWS-EC2-001` |
| `title` | string | from rule metadata |
| `severity` | `critical\|high\|medium\|low\|info` | from metadata; never changed by config |
| `csp`, `service` | string | from metadata |
| `status` | `open\|excepted` | `excepted` only while a valid exception applies |
| `message` | string | from the violation; must not contain sensitive values |
| `resource` | object | `address`, `type`, `module`, `provider` |
| `root_module` | string | scan-root-relative dir of the input document |
| `location` | object | `file`, `start_line`, `start_column`, `end_line`, `end_column` (the attribute range if known, else the block) |
| `attribute_path` | array\|null | from the violation |
| `remediation` | string | from metadata |
| `frameworks` | object | framework → control IDs, from metadata |
| `references` | array | URLs from `related_resources` |
| `policy_source` | object | `name`, `version`, `digest` (`builtin` uses the binary version) |
| `fingerprint` | string | `sha256(rule_id + root_module + resource.address + attribute_path)`. Line numbers are excluded so it survives edits above the resource. |
| `exception` | object\|null | `id`, `owner`, `reason`, `expires`, `ticket` |
| `ai_suggestion` | object\|null | see `iace-ai-remediation` |

Report-level fields (JSON/SARIF): `schema_version`, `tool` (`name`, `version`, `commit`),
`policy_sources[]`, `summary` (counts by severity and status, plus blocking count), `warnings[]`
(expiring or stale exceptions, deprecated rules), `coverage_gaps[]`, and `inputs[]` (root modules
or plan files scanned). Timestamps come only from the injected clock.

## CLI
Built with cobra, with kebab-case flags. Precedence: flags > env (`IACE_*`) > `.iace.yaml` > defaults.

```
iace scan [PATH ...]                scan Terraform directories (default ".")
  -o, --output FORMAT[=FILE]        repeatable; text|json|sarif|junit|markdown|github; default text→stdout
  -c, --config FILE                 repo config (default: discover .iace.yaml)
      --org-config FILE             org baseline; repo config may only tighten it
      --fail-on SEVERITY            critical|high|medium|low|none; overrides config
      --min-severity SEVERITY       hide findings below this severity
      --var-file FILE / --var K=V   Terraform variables (repeatable)
      --plan FILE [--source DIR]    scan plan JSON instead of HCL (M9)
      --rule ID                     run only these rules (repeatable; for debugging)
      --offline                     forbid all network access (cached bundles only)
      --fail-on-gaps                exit 2 when coverage gaps exist
      --ai-fix                      request verified AI fix suggestions (opt-in, M10)
      --timeout DURATION            whole-run timeout (default 5m)
      --log-level LEVEL --log-format text|json --no-color
iace inspect PATH [--json]          print the normalized input document(s)
iace rules list [--csp X]           list loaded rules
iace rules show ID                  full metadata and remediation for one rule
iace init [--force]                 scaffold a commented .iace.yaml
iace policy test|check|build PATH   tools for policy authors (M8)
iace fix --ai [--write] [PATH]      apply verified AI fixes to the working tree (M10)
iace version [--json]
```

Rules:
- Reports go to **stdout** (or files). Logs, progress and warnings go to **stderr**. Never mix them:
  CI pipes stdout into other tools.
- Non-interactive by default. No prompts in any command, because CI has no TTY.
- `--help` on every command has at least one runnable example.
- Colour only when stderr/stdout is a TTY and `NO_COLOR` is unset.
- A bare `iace` prints the root help to stdout and exits 0.

### `iace version`
Prints `iace <version> (commit <commit>, built <date>)`. With `--json` it prints a versioned
document, keys in this order:
```json
{
  "schema_version": "1",
  "name": "iace",
  "version": "v0.1.0",
  "commit": "<full git sha>",
  "date": "<commit date, RFC 3339>"
}
```
Release builds set the last three with `-ldflags -X …/internal/version.{Version,Commit,Date}`;
unset, each is `"dev"`. Changes follow the `schema_version` rules: adding a field keeps `"1"`,
while renaming or removing one needs `"2"` and an ADR.

## Exit codes
| code | meaning |
|---|---|
| 0 | scan completed; no open finding at or above `fail_on` |
| 1 | scan completed; at least one open finding at or above `fail_on` |
| 2 | could not complete a trustworthy scan: usage, config, Terraform parse, policy load/compile/eval, bundle verification, timeout, internal error, or gaps with `--fail-on-gaps` |

Exit 2 takes precedence over 1. Errors print one line to stderr naming the file, rule or flag,
plus a hint. With `--log-level debug` they include detail and the chain of wrapped causes.

## Environment variables
| var | purpose |
|---|---|
| `IACE_CONFIG`, `IACE_ORG_CONFIG` | config paths |
| `IACE_LOG_LEVEL`, `IACE_LOG_FORMAT`, `NO_COLOR` | logging and colour |
| `IACE_CACHE_DIR` | bundle and AI cache (default `$XDG_CACHE_HOME/iace`) |
| `IACE_OFFLINE` | same as `--offline` |
| `IACE_TRUSTED_KEYS` | extra bundle verification keys, supplied by CI (M8) |
| standard AWS configuration (`AWS_REGION`, `AWS_PROFILE`, credential env vars, SSO, instance role, web identity) | Amazon Bedrock region and credentials for AI suggestions (M10, D-05); never read unless AI is enabled |
