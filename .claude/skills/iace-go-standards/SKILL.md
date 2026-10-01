---
name: iace-go-standards
description: Go engineering standards for iac-compliance-enforcer (iace) — toolchain and pinned tools, project layout, error handling, context, logging with slog, concurrency, safe file access, dependency and license policy, CLI conventions, performance and build flags, plus the golangci-lint v2 config. Use this whenever you write, review or refactor Go code in this repository, add a dependency, set up tooling, or decide how a Go API should look, even for one-line changes.
---

# Go standards for iace

The goal is code that a security reviewer can trust at a glance: boring, explicit, and testable,
with no hidden I/O. When a rule here conflicts with convenience, the rule wins. If you believe a
rule is wrong, change it via an ADR rather than ignoring it.

## Toolchain
- Use the latest stable Go release, with at least 1.24 for `tool` directives and `os.Root`.
  The `go` directive in go.mod is the minimum we test with, and a `toolchain` line pins the exact version.
- Dev tools are pinned in a **separate module**, `tools/go.mod`, so linters never mix
  dependencies into the product's module graph:
  `go get -modfile=tools/go.mod -tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint@vX.Y.Z`,
  run with `go tool -modfile=tools/go.mod golangci-lint run`. Pin the same way:
  golangci-lint v2, govulncheck, regal, actionlint and `opa`. Keep `opa` at **exactly** the version of
  the OPA library in go.mod, so `opa test` judges policies with the same engine iace embeds.
- Lint and format: copy [assets/golangci.yml](assets/golangci.yml) to `.golangci.yml`.
  Formatting is gofumpt plus goimports via `golangci-lint fmt`.
- Build: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X …/internal/version.Version=…"`.
  This gives a static, reproducible binary.

## Layout and APIs
- Follow the package layout in `iace-architecture`. Everything is under `internal/` until we
  deliberately publish an API. `cmd/iace/main.go` stays under ~20 lines.
- Packages are named for what they provide (`engine`, `report`), never `util`, `common` or `helpers`.
  Each package has a doc comment stating its responsibility and what it must not do.
- Define small interfaces in the **consumer** package. Accept interfaces and return concrete types.
  Constructors take required dependencies as parameters and optional ones via functional options.
- No global mutable state, no `init()` with side effects, no singletons. Clock, filesystem root,
  writers, logger and HTTP client are injected, which is what makes golden tests and fault
  injection possible.

## Errors
- Wrap with context at every boundary: `fmt.Errorf("parse %s: %w", rel, err)`. Inspect with
  `errors.Is` and `errors.As`, never string matching.
- User-facing failures use typed errors in `internal/model` (e.g. `ConfigError`,
  `PolicyError{RuleID, File, Line}`, `ParseError`) so the CLI can map them to exit code 2 and a
  one-line message with a hint.
- Never panic on input. The only `recover` lives in `internal/cli`, where it converts a panic to
  exit 2 with "internal error, please report" plus the stack trace at debug level.
- An error is never downgraded to "no findings". If a component cannot finish, the scan fails (fail closed).

## Context, timeouts, cancellation
- `ctx context.Context` is the first parameter of anything that does I/O, evaluation or might block.
- Respect cancellation in loops over files and resources. Policy evaluation and HTTP calls get
  their own deadlines derived from the run timeout.

## Logging
- `log/slog` only, written to **stderr** and configured in `cli` (`--log-level`, `--log-format`).
  Use key-value pairs and `slog.*Context` where a context exists.
- Log addresses, file paths, rule IDs and counts. **Never log attribute values, variable values,
  tokens or prompts**, because Terraform values routinely contain secrets. When in doubt, log the key, not the value.

## Concurrency
- Use `golang.org/x/sync/errgroup` with `SetLimit(runtime.GOMAXPROCS(0))` for per-root-module
  work. The first error cancels the rest.
- Shared read-only state (the prepared OPA query, metadata) is fine. Anything mutable is owned by
  one goroutine or guarded. Tests run with `-race`.
- Results from concurrent work are **sorted before output**, so completion order never leaks into reports.

## Files and I/O
- All reads of scanned content go through `internal/fsutil`, built on `os.Root` (`os.OpenRoot`).
  It confines access to the scan root (no `..` or symlink escape), enforces per-file and total
  size limits with `io.LimitReader`, and rejects non-regular files. The forbidigo rule in
  the lint config enforces this.
- Write output files atomically (temp file in the same dir, then rename) with mode 0644. Caches
  and anything containing AI data get 0600 inside 0700 directories.
- stdout is reserved for reports. Everything else goes to stderr.

## Dependencies and licenses
Prefer the standard library. A new dependency needs all of the following, stated in the commit
message (and in an ADR if it is large):
- actively maintained, with a release or commit in the last 12 months
- a license on the allowlist: Apache-2.0, MIT, BSD-2/3, ISC or MPL-2.0. Never GPL, AGPL or **BUSL**.
- pure Go (no cgo) and clean under `govulncheck`
- no `init()`-time network or filesystem access

Expected core dependencies (check versions and maintenance when adding them):
`open-policy-agent/opa/v1`, `hashicorp/hcl/v2`, `zclconf/go-cty`, `hashicorp/terraform-json`,
`spf13/cobra`, `go.yaml.in/yaml/v3`, `santhosh-tekuri/jsonschema/v6`, `golang.org/x/sync`,
`anthropics/anthropic-sdk-go` (M10), and for tests only `google/go-cmp` and
`rogpeppe/go-internal/testscript`.

**Never copy code from hashicorp/terraform**, because it is BUSL-1.1. Code adapted from MPL-2.0
projects (OpenTofu, hcl) keeps its license header and attribution in the file.

## CLI conventions
cobra commands live in `internal/cli`. Flags are kebab-case, and each has an `IACE_*` env
equivalent where it makes sense. Commands are non-interactive. Every command's `Example` field
holds runnable examples. Exit codes are decided only in `internal/cli` (see `iace-architecture`).

## Performance
- Measure before optimizing (`go test -bench`, `-cpuprofile`, `-memprofile`). Record budgets and
  results in PROGRESS.
- Known hot spots: converting the input document for OPA (do it **once** per document with
  `ast.InterfaceToValue` and reuse it); repeated `filepath.Walk` (walk once, then index); and
  regex compilation (compile at package level, since `regexp` in Go is RE2 and safe from ReDoS).
- Preallocate slices whose size you know, and avoid reflection-heavy conversions in loops.

## Code review checklist (Go)
- [ ] Errors are wrapped with context; no ignored errors (`_ =` needs a comment explaining why).
- [ ] No new global state; clock, filesystem and writers are injected.
- [ ] No secret values reachable by logs or reports.
- [ ] Context propagated; loops cancellable; goroutines bounded and joined.
- [ ] Output sorted and deterministic.
- [ ] New dependency justified (maintenance, license, no cgo).
- [ ] Public identifiers have doc comments; package doc states responsibility.
