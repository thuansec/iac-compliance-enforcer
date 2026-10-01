---
name: iace-testing
description: Test strategy for iac-compliance-enforcer (iace) — test-first workflow, Go table tests, Rego unit tests, the policy fixture harness (pass/fail Terraform per rule), golden files with -update, CLI end-to-end tests with testscript, fuzzing, benchmarks and performance budgets, adversarial/security tests, fixtures conventions, determinism and no-network rules, and coverage targets. Use this whenever writing or changing tests, adding fixtures, deciding how to prove an acceptance criterion, investigating a flaky or slow test, or before implementing any task (tests come first).
---

# Testing iace

## Test-first, always
For each acceptance bullet: write the test, run it, and watch it fail **for the right reason**
(an assertion about behaviour, not a compile error in the test). Then implement. A test that never
failed has never shown it can catch the bug it guards.

## The test pyramid here
| layer | where | proves |
|---|---|---|
| Go unit (table-driven) | `internal/**/_test.go` | component logic: evaluation, matching, decoding, merging |
| Rego unit | `policies/**/_test.rego` | rule logic on synthetic input (see `iace-rego-policies`) |
| Policy fixtures | `testdata/policies/<RULE-ID>/{fail,pass}/` plus `internal/engine/fixtures_test.go` | real HCL → parser → engine triggers exactly the expected rule |
| Golden | `testdata/**/*.golden*` | input documents, every report format, prompts |
| CLI e2e | `cmd/iace/testdata/script/*.txtar` with `github.com/rogpeppe/go-internal/testscript` | flags, exit codes, files written, stdout/stderr split |
| Fuzz | `Fuzz*` in parser, config, bundle and exception-glob packages | no panics or hangs on hostile input |
| Bench | `Benchmark*` in terraform and engine | budgets from `iace-architecture` |

## Conventions
- **Table tests** with named cases and `t.Run`. Use `t.Parallel()` when no shared state is touched.
  Compare structs with `github.com/google/go-cmp/cmp` and print diffs.
- **No hidden inputs**: no network, no real clock (inject `clock.Fixed`), no reads of `$HOME`
  or real env (`t.Setenv`), temp dirs only via `t.TempDir()`, and no dependence on test order.
  Everything passes with `go test -race -shuffle=on -count=1 ./...`.
- **No network, enforced**: HTTP clients are injected, and tests use `httptest.Server`.
  Anything needing real network (fixture validation, live AI) sits behind a build tag (`live`,
  `fixtures`) and the matching BACKLOG loop setting.
- **Errors are tested as carefully as successes**: every `ConfigError`, `PolicyError` and
  `ParseError` path has a case asserting the message names the file, rule or field.

## Policy fixture harness (built in T-0205)
- Each `testdata/policies/<RULE-ID>/fail/` holds minimal Terraform that violates the rule, plus
  `expected.yaml` listing the violating addresses (and attribute paths). `pass/` holds compliant
  variants: explicit secure values, secure defaults, and account-level settings.
- The harness scans each directory with the real loader and engine. It asserts that `fail`
  yields exactly the expected findings for that rule, and that `pass` yields none for it.
- **Completeness check**: the harness fails if any loaded rule lacks a `fail` or `pass` directory,
  or if a fixture directory names an unknown rule. New rules can't skip fixtures.
- Fixtures are valid Terraform for every supported provider major, `terraform fmt`-clean, with
  `required_providers` pinned and fake but realistic values (account `123456789012`,
  `example.com`, `10.0.0.0/16`). **No real secrets.** For secret-detection rules, use obviously
  fake values that still match the pattern under test, created with the Write tool, not echoed
  through shell commands.

## Golden files
- Update with `go test ./<pkg> -run <Test> -update`. Review the golden diff as carefully as code,
  because a golden file is an assertion.
- Goldens must be deterministic: fixed clock, sorted output, no absolute paths (use the scan
  root's relative paths), no versions that change per build (inject `version=test`).

## CLI end-to-end (testscript)
```txtar
# scanning a failing repo exits 1 and writes SARIF
! exec iace scan -o text -o sarif=out.sarif repo
stdout 'IACE-AWS-EC2-001'
exists out.sarif
-- repo/main.tf --
resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}
```
Register `iace` via `testscript.Main` in `TestMain`, so scripts run the real command tree in-process.
Assert exit codes with `!` (non-zero), stdout and stderr separately, and files on disk.

## Fuzzing
- Targets: `FuzzParseFile`, `FuzzEvaluate`, `FuzzLoadConfig`, `FuzzReadBundle`, `FuzzAddressGlob`.
- Seed corpora in `testdata/fuzz/<Target>/` come from fixtures and every crasher ever found.
- CI runs each target briefly (`-fuzztime=30s`, nightly). T-1102 runs 10 minutes each. Every crash
  becomes a regression seed plus a fix.

## Benchmarks and budgets
`internal/terraform/testgen` generates synthetic modules (N resources, mixed types, modules,
count/for_each). Benchmarks report ns/op and allocations. Budget checks run in a nightly job
(timing is noisy on PR runners), with results recorded in PROGRESS when a milestone touches performance.

## Coverage
- Go: ≥ 80% overall, and ≥ 85% for `internal/engine`, `internal/terraform`, `internal/config`,
  `internal/exceptions` and `internal/policy`. `gates.sh full` enforces the overall number.
- Rego: ≥ 90% (the gate). Rule files should reach 100%.
- Coverage is a floor, not a goal. Reviews check that tests assert behaviour, not just execute lines.

## Flaky tests
Never `t.Skip` to get green. If a test is flaky, fix the nondeterminism (time, order, ports,
goroutine races) in the current task, or open a task, mark the current one blocked, and explain.
