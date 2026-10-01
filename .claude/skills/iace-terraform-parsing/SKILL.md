---
name: iace-terraform-parsing
description: How iace loads Terraform without executing it — safe discovery of root modules, HCL/JSON parsing with hashicorp/hcl/v2, static evaluation of variables, locals, functions, count/for_each/dynamic blocks and local modules, reference and provider-version extraction, plan JSON ingestion, source mapping, unknown/sensitive tracking, and normalization into the input document. Use this for any work in internal/terraform, for questions like "how do we handle modules / tfvars / for_each / unknown values", for parser fuzzing, or when a policy misbehaves because the input document looks wrong.
---

# Loading Terraform safely

## The prime directive
**Never execute anything from the scanned repository.** That rules out `terraform init`,
`plan` or `validate` on scanned code, downloading modules, starting provider plugins, and running
hooks. Provider plugins and `external` data sources run arbitrary code during `plan`, and module
sources pull remote code. iace scans untrusted pull requests, so static analysis is the default
and the only mode that touches scanned code. Plan JSON (M9) is accepted only as a file that a
trusted pipeline already produced.

(Dev tooling such as `iace-cloud-controls/scripts/provider_schema.sh` may run `terraform init` on a
config **we** generate with official providers. That is not scanned code.)

## Pipeline (internal/terraform)
1. **Discover**: walk the scan root through `internal/fsutil` (`os.Root`). Skip `.terraform/`,
   `.git/`, hidden dirs and vendored test fixtures when configured. Don't follow symlinks outside
   the root. Enforce limits: 5 MiB per file, 10k files, 32 module levels. A limit hit becomes a
   `limit_exceeded` coverage gap, plus exit 2 when `--fail-on-gaps` is set. A directory with
   `*.tf`/`*.tf.json` that no other scanned directory calls as a local module is a **root module**.
2. **Parse**: `hclparse.Parser` (`ParseHCLFile`, `ParseJSONFile`). Keep every diagnostic.
   Error-severity diagnostics in a root module make that root a `parse_error` gap, and the scan
   exits 2, because Terraform itself would refuse the file. `*_override.tf` files are merged with
   Terraform's override semantics, or reported as a gap until that is implemented.
3. **Decode schema-less**: we have no provider schemas at scan time. Walk `hclsyntax.Body`
   generically: attributes become values, and nested blocks become lists of objects (matching
   plan JSON). Meta-arguments (`count`, `for_each`, `provider`, `depends_on`, `lifecycle`,
   `provisioner`, `connection`) go to `meta`, not `values`.
4. **Evaluate**: build an `hcl.EvalContext` per module instance, with variables, locals,
   `path.*`, `terraform.workspace = "default"`, `count.index`, `each.*` and a curated function
   table. Anything unresolvable becomes **unknown** (`cty.UnknownVal`), never an error. See
   [references/hcl-evaluation.md](references/hcl-evaluation.md).
5. **Expand**: count, for_each and dynamic blocks; local module calls, recursively.
6. **Extract**: references per attribute (transitive through locals and module inputs), provider
   local-name → source mapping, `.terraform.lock.hcl` versions, `terraform {}` settings and backend.
7. **Normalize**: produce one input document v1 per root module
   (`iace-architecture/references/input-document.md`): cty → JSON-compatible values,
   unknown/sensitive paths, source ranges, coverage gaps. Sort everything that ends up in arrays.

## Key decisions (keep consistent)
- **Unknown beats guessing.** If a value depends on a resource attribute, a data source, an
  unsupported function, or an unresolved module output, it is unknown. Record the path and move on.
  Policies decide how to treat unknowns. The parser never invents defaults.
- **Absent stays absent.** Don't inject provider defaults (we have no schemas). Policies own
  defaults, per provider major version, via `tf.provider_major`.
- **Sensitive tracking.** Values derived from `sensitive = true` variables, or from functions over
  them, are marked by path, and cty marks are propagated. Literal secrets are detected later by
  policies and redaction, not by the parser.
- **Numbers** are converted to `json.Number`, so large integers (account IDs, ports) don't lose precision.
- **Determinism.** Iterate files lexically. Sort map keys, instance keys and resources by address.
  Never let map iteration order reach output.
- **Coverage honesty.** Every place we give up (unresolved module, unknown count, limit hit,
  parse error) adds a `coverage_gaps` entry that reporters show. Users must be able to see what was **not** checked.

## Modules
- Local sources (`./`, `../`): resolve relative to the calling module, but the result must stay
  inside the scan root (via `os.Root`). An escape leaves the module unresolved and records a gap.
- Registry/git/http sources: resolve **only** through an existing `.terraform/modules/modules.json`
  (written by a previous `terraform init` in a trusted context), and only to directories inside the
  scan root. Otherwise the module is unresolved: its outputs are unknown, and a gap is recorded.
- Module inputs are evaluated in the caller's context. Outputs are evaluated in the module's
  context and exposed to the caller. `count`/`for_each` on module calls produce
  `module.x[0]`/`module.x["k"]` instance prefixes. Use a depth limit of 32 and cycle detection by
  absolute directory.

## Plan JSON (M9)
Read with `github.com/hashicorp/terraform-json`. Details and the mapping table are in
[references/plan-json.md](references/plan-json.md). Plan mode must produce the same input-document
shape, so the same policies run unchanged.

## Testing expectations
- Fixtures live in `testdata/terraform/<scenario>/`: small, realistic, `terraform fmt`-clean, with
  pinned `required_providers`, fake values, and no secrets.
- Golden input documents (`*.golden.json`) for e2e scenarios, regenerated with `go test … -update`
  and reviewed in the diff.
- Fuzz targets: `FuzzParseFile` (bytes → parse+decode must not panic), and `FuzzEvaluate` (small
  modules with random expressions). Seed corpora go in `testdata/fuzz/`.
- Adversarial tests: symlink escape, `../` module sources, a 100 MB file, deeply nested
  expressions, `count = 1e9`, and recursive locals and modules.
- Benchmark: the synthetic generator in `internal/terraform/testgen` creates N-resource modules.
  The budget is in `iace-architecture`.

## Gotchas
- `.tf.json` is ambiguous without a schema: a nested JSON object may be a block or a map
  attribute. Treat objects under keys known to be blocks in Terraform's JSON syntax
  (`resource`, `module`, `variable`, …) structurally. Represent nested resource objects as given,
  and normalize single objects to one-element lists only where an HCL block would appear. Document
  each heuristic in the reference.
- Heredoc and `jsonencode` policies: evaluate `jsonencode(...)` so IAM-style rules can
  `json.unmarshal` strings. A templated heredoc with unknown interpolations is unknown.
- Provider for a resource: the explicit `provider = aws.eu` meta-argument wins; otherwise the
  type prefix (`aws_` → local name `aws`) is mapped through `required_providers` (default
  namespace `hashicorp`).
- Terraform version features (e.g. `import`/`moved`/`removed`/`check` blocks, provider-defined
  functions `provider::aws::...`): parse them without failing. Provider functions evaluate to unknown.
