# Plan JSON ingestion (M9)

Input: the output of `terraform show -json tfplan`, produced by a **trusted** pipeline that already
ran `terraform plan` with credentials. iace never generates plans itself.

## Validation
- Decode with `github.com/hashicorp/terraform-json` (`tfjson.Plan`). Call `Validate()`, then
  check that the `format_version` major is `1`. Reject other majors with exit 2 and a clear message.
- Size limit: 200 MiB by default (flag-adjustable). Stream from disk; never read stdin implicitly.

## Mapping to input document v1
| input document | plan JSON source |
|---|---|
| `resources[]` (managed) | `resource_changes[]` where `change.actions` ≠ `["delete"]` (create, update, no-op, replace) |
| `values` | `change.after` |
| `unknown` | paths where `change.after_unknown` is `true` (walk nested objects and arrays) |
| `sensitive` | paths where `change.after_sensitive` is `true` |
| `resources[]` (data) | `prior_state.values` / `planned_values` data resources, with `mode: data` |
| `address`, `type`, `name`, `index`, `module` | `resource_changes[].address`, `.type`, `.name`, `.index`, `.module_address` |
| `provider` | `.provider_name` |
| `references` | `configuration.root_module` (recursing through `module_calls`): `resources[].expressions.<attr>.references`, made module-qualified, with attribute suffixes stripped |
| `provider_versions` | not in the plan: read `.terraform.lock.hcl` from `--source` if given |
| `terraform.backend` | not in the plan. Read it from `--source` HCL if given, otherwise leave it empty. |
| `source` | parse `--source` HCL and match by config address (module path + type + name). Otherwise use the module dir and a coverage gap. |

Nested blocks in `after` are already lists of objects, which is exactly the v1 shape.

## Parity expectations
For fixtures whose values are fully known statically, HCL mode and plan mode must yield
**identical findings** (T-0904). Commit golden plan JSON files that were generated once by a
human or CI with fake credentials and a local backend. Tests never run terraform.

## Pitfalls
- `after_unknown` and `after_sensitive` mirror the structure of `after`, but can be `true` at a
  parent, meaning the whole subtree is unknown or sensitive. Record the parent path only, since
  `tf.is_unknown` handles ancestor matching.
- Resources being replaced appear once with actions `["delete","create"]` or
  `["create","delete"]`. Keep them, because the "create" side is the future state.
- Module addresses can carry instance keys: `module.app["blue"].aws_s3_bucket.b`.
