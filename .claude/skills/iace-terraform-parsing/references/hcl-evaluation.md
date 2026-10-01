# Static evaluation details

## Variable precedence (lowest → highest), as in Terraform
1. `default` in the `variable` block
2. `terraform.tfvars`, then `terraform.tfvars.json`
3. `*.auto.tfvars` / `*.auto.tfvars.json`, in lexical filename order
4. `--var-file` flags, in the order given
5. `--var K=V` flags, in the order given

`TF_VAR_*` environment variables are **not** read by default, for reproducibility (CI and laptops
would otherwise disagree). Add `--use-tf-var-env` only if a real need appears, and write an ADR.

A variable with no value from any source is **unknown**, not an error. Plain `terraform validate`
would complain, but a scanner should still evaluate everything else.

Type constraints: apply `convert.Convert` to the declared type when the value is known. If that
fails, record a warning and keep the value unconverted. Do not fail the scan.

`sensitive = true` marks the value. Propagate cty marks through expressions, and list the final
paths in the resource's `sensitive` array.

## Locals
Build a dependency graph from each local's expression traversals. Evaluate in topological order.
A cycle makes every local in it unknown and adds a warning (Terraform would reject the config, so
we only need to avoid looping). Locals referencing resources or data sources are unknown but carry
their **references**, so attributes using the local still get the right `references` entry.

## Function table
Evaluate with go-cty's `function/stdlib` where semantics match Terraform. Register each function
under its Terraform name, and document the table in code with a test per function.

| group | functions (initial set) |
|---|---|
| string | `format`, `formatlist`, `join`, `split`, `lower`, `upper`, `title`, `trimspace`, `trim`, `trimprefix`, `trimsuffix`, `replace` (plain and regex), `substr`, `startswith`, `endswith`, `strcontains` |
| collection | `concat`, `merge`, `flatten`, `distinct`, `keys`, `values`, `lookup`, `element`, `length`, `contains`, `coalesce`, `coalescelist`, `compact`, `slice`, `zipmap`, `setunion`, `tolist`, `toset`, `tomap`, `range` (capped) |
| type | `tostring`, `tonumber`, `tobool`, `try`, `can`, `type` (unknown) |
| encoding | `jsonencode`, `jsondecode`, `yamlencode` (optional), `base64encode`, `base64decode` |
| network | `cidrsubnet`, `cidrhost`, `cidrnetmask` (pure functions; useful for SG/NSG rules) |
| filesystem | `file`, `fileexists`, `templatefile`: **only** inside the module directory via `os.Root`, size-capped (1 MiB), with no symlink escape |

Anything else, including `timestamp()`, `uuid()`, `bcrypt()`, provider-defined functions and
`plantimestamp()`, evaluates to **unknown**. Add an `unsupported_function` gap once per function
name per module, not per call.

Guards: cap `range()` and `formatlist` output length, string results above 1 MiB, and recursion
depth. A cap that triggers yields unknown plus a `limit_exceeded` gap.

## count / for_each
- `count` known integer n: instances `[0..n-1]`. `count = 0` produces no instances (a common
  feature-flag pattern, and correct).
- `for_each` known map or set of strings: one instance per key, sorted, `["key"]`.
- Unknown count or for_each: **one** placeholder instance with `index: null`, `meta.count_unknown`
  or `meta.for_each_unknown` set to true, and an address like `aws_s3_bucket.b[*]`. Its values are
  evaluated with `count.index` / `each.*` unknown, so policies still see static attributes.
- Cap instances at 10,000 per resource. Above that, emit a `limit_exceeded` gap and keep the first 10,000.

## dynamic blocks
`dynamic "ingress" { for_each = …; content { … } }` expands into `ingress` list entries using
the iterator name (default: the block label). An unknown `for_each` produces a single entry whose
attributes are evaluated with an unknown iterator, and the path `["ingress"]` is marked unknown
(the number of entries is unknown).

## Source ranges
- Block range: from the block's `DefRange().Start` to the end of its body's `SrcRange`.
- Attribute range: `hcl.Attribute.Range`, keyed by the dot-joined normalized path
  (`metadata_options.0.http_tokens`). For dynamic blocks, point at the `content` attribute.
- Resources inside modules: `source.file`/`range` point at the module's file, and
  `source.module_call` points at the call site. Reporters can then show both.

## Provider versions
Parse `.terraform.lock.hcl` with hclparse: `provider "registry.terraform.io/hashicorp/aws" { version = "6.12.0" … }`.
If there is no lock file, leave `provider_versions` empty. Policies then fall back to the
conservative default via `tf.provider_major(r) == -1`. Record the `required_providers` constraints
in `terraform.required_providers` either way.
