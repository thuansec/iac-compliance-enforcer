# Input document v1 (Go → Rego contract)

One input document is produced per **root module** (HCL mode) or per **plan file** (plan mode)
and passed to OPA as `input`. The same rules must work on both modes, so both normalize into this
shape. The JSON Schema lives in `schemas/input.v1.json` and must match this page.

## Design rules
1. **Shape mirrors Terraform plan JSON `values`.** Attributes are JSON values, and nested blocks
   are **arrays of objects** even when at most one block is allowed (`metadata_options` →
   `[{...}]`). Policies then index blocks the same way in both modes.
2. **Unknown is explicit.** A value that cannot be known statically (an unresolved reference, an
   unsupported function, known-after-apply, an unresolved module) is stored as `null`, and its
   path is listed in `unknown`. Policies must check `tf.is_unknown` before judging a value, so an
   unknown value never becomes a false positive or a silent pass.
3. **Absent means absent.** In HCL mode, attributes not written in the configuration are simply
   missing. Policies apply provider defaults explicitly (see `iace-rego-policies`). In plan mode
   the provider has already filled in defaults, so values are present.
4. **Sensitive values stay in, flagged.** Policies may inspect them (to find hardcoded
   secrets, for example). Paths listed in `sensitive` are never printed by reporters or sent to AI.
5. **Paths** are arrays of strings (attribute or block names) and integers (list indexes):
   `["ingress", 0, "cidr_blocks"]`. Where a path is a JSON object key (`references`,
   `source.attributes`), it is written dot-joined: `"ingress.0.cidr_blocks"`.
6. **Addresses** follow Terraform syntax: `module.net.aws_security_group.web[0]`,
   `aws_s3_bucket.b["logs"]`, `data.aws_iam_policy_document.admin`.
7. **File paths** are relative to the scan root, slash-separated, and never absolute.

## Top level
| field | type | notes |
|---|---|---|
| `schema_version` | `"1"` | |
| `source` | object | `kind` (`hcl`\|`plan`), `root_module` (scan-root-relative dir), `plan_file` (plan mode) |
| `terraform` | object | `required_version`, `backend` `{type, values, unknown}`, `required_providers` `{local_name: {source, version}}` |
| `provider_versions` | object | provider source address → exact version from `.terraform.lock.hcl` (HCL) or the plan |
| `providers` | array | provider configurations: `{local_name, alias, source, values, unknown, sensitive, source_range}` |
| `resources` | array | managed resources **and** data sources (`mode`); see below |
| `module_calls` | array | `{address, source, version, resolved, reason, source_range}`, used for module supply-chain rules |
| `variables` | array | `{name, module, sensitive, has_default, type}`. **No values**: they are already inlined. |
| `outputs` | array | `{name, module, sensitive, references, source_range}` |
| `coverage_gaps` | array | `{kind, detail, file, line}` with kind ∈ `parse_error`, `unresolved_module`, `unknown_expansion`, `limit_exceeded`, `unsupported_function` |

## Resource object
| field | type | notes |
|---|---|---|
| `address` | string | full instance address, unique within the document |
| `base_address` | string | `address` without this resource's own instance key (`aws_s3_bucket.b[0]` → `aws_s3_bucket.b`) |
| `mode` | `managed`\|`data` | |
| `type`, `name` | string | |
| `index` | number\|string\|null | instance key; `null` when there is no count/for_each, or when it is unknown |
| `module` | string | module path such as `module.net`, or `""` for root |
| `provider` | string | source address, e.g. `registry.terraform.io/hashicorp/aws` |
| `provider_config` | string | `aws.eu` when aliased; `""` for the default config |
| `values` | object | attribute values (rule 1) |
| `unknown` | array of paths | rule 2. An unknown ancestor path implies all descendants are unknown. |
| `sensitive` | array of paths | rule 4 |
| `references` | object | dot-joined attribute path → list of referenced addresses (see below) |
| `meta` | object | `count_unknown`, `for_each_unknown`, `depends_on`, `lifecycle` (`prevent_destroy`, `ignore_changes`) |
| `source` | object | `file`, `range`, `attributes` (dot-joined path → range), `module_call` `{file, range}` when inside a module |

`range` = `{start_line, start_column, end_line, end_column}` (1-based; columns in bytes).

### References
For each attribute whose expression refers to other resources or data sources, record the target
addresses, **module-qualified** and without the attribute suffix:
`bucket = aws_s3_bucket.logs.id` → `{"bucket": ["aws_s3_bucket.logs"]}`.
- If the index is statically known, keep it (`aws_s3_bucket.logs[0]`). Otherwise use the base
  address. Policies match targets with `tf.referencing`, which accepts either form.
- References propagate **through locals and module input variables**, so `bucket = local.b` where
  `local.b = aws_s3_bucket.logs.id` still yields `aws_s3_bucket.logs`.
- In plan mode, take them from `configuration.*.expressions.*.references`.

## Example (HCL mode, abridged)
```json
{
  "schema_version": "1",
  "source": {"kind": "hcl", "root_module": "infra/prod"},
  "terraform": {
    "required_version": ">= 1.6",
    "backend": {"type": "s3", "values": {"bucket": "tf-state", "encrypt": true}, "unknown": []},
    "required_providers": {"aws": {"source": "registry.terraform.io/hashicorp/aws", "version": "~> 6.0"}}
  },
  "provider_versions": {"registry.terraform.io/hashicorp/aws": "6.12.0"},
  "providers": [],
  "resources": [
    {
      "address": "aws_instance.web",
      "base_address": "aws_instance.web",
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "index": null,
      "module": "",
      "provider": "registry.terraform.io/hashicorp/aws",
      "provider_config": "",
      "values": {
        "ami": "ami-0123456789abcdef0",
        "instance_type": "t3.micro",
        "subnet_id": null,
        "metadata_options": [{"http_tokens": "optional"}]
      },
      "unknown": [["subnet_id"]],
      "sensitive": [],
      "references": {"subnet_id": ["aws_subnet.private"]},
      "meta": {"count_unknown": false, "for_each_unknown": false, "depends_on": [], "lifecycle": {}},
      "source": {
        "file": "infra/prod/compute.tf",
        "range": {"start_line": 1, "start_column": 1, "end_line": 12, "end_column": 2},
        "attributes": {
          "metadata_options.0.http_tokens": {"start_line": 9, "start_column": 5, "end_line": 9, "end_column": 29}
        }
      }
    }
  ],
  "module_calls": [],
  "variables": [{"name": "env", "module": "", "sensitive": false, "has_default": true, "type": "string"}],
  "outputs": [],
  "coverage_gaps": []
}
```

## Plan-mode differences
- `values` = `resource_changes[].change.after`, with `unknown` and `sensitive` taken from
  `after_unknown` and `after_sensitive`. Resources whose only action is `delete` are excluded.
- Provider defaults are already present in `values`.
- `source` is filled by parsing the HCL in `--source <dir>` and matching config addresses. If it
  cannot be matched, `source.file` is the module directory and a coverage gap is recorded.

## Evolution
Additive fields are allowed within v1, and policies must ignore unknown fields. Removing, renaming
or changing the meaning of a field requires `schema_version: "2"`, an ADR, and a migration of
all built-in policies in the same change.
