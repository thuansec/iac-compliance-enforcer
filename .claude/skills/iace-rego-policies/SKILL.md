---
name: iace-rego-policies
description: How to write, test and maintain iace's Rego (OPA v1) compliance policies — file layout, package naming, required METADATA annotations, the deny/violation contract, the iace.lib.tf helper library, correct handling of unknown values, absent attributes and provider-version defaults, cross-resource checks, opa test coverage, Regal linting, performance and rule lifecycle. Use this whenever creating or changing a policy under policies/, adding a rule for any AWS or Azure control, writing Rego tests, reviewing a rule that misfires (false positive or false negative), or helping authors of the central or org policy bundles.
---

# Writing iace policies

A policy is the product. A rule that silently never fires is worse than no rule, because it
reports "compliant". Every rule here is written to fail loudly in tests when it is wrong.

## Layout and naming
Directories mirror package paths. This is Regal's `directory-package-mismatch` rule, and it means
a package can always be found from its name.
```
policies/
  embed.go                    # //go:embed iace capabilities.json
  capabilities.json           # generated (iace-opa-engine)
  iace/lib/tf/tf.rego         # helper library (+ tf_test.rego)
  iace/rules/<csp>/<service>/<rule_name>/<rule_name>.rego        # one rule package
  iace/rules/<csp>/<service>/<rule_name>/<rule_name>_test.rego   # its tests (package …_test)
.regal/config.yaml            # from assets/regal-config.yaml
testdata/policies/<RULE-ID>/{fail,pass}/*.tf   # realistic fixtures (Go e2e harness)
```
- Use one rule per package and per directory. Package: `iace.rules.<csp>.<service>.<rule_name>`,
  in snake_case and describing the requirement (`imdsv2_required`, not `check1`).
- Rule IDs: `IACE-<CSP>-<SERVICE>-<NNN>`, taken from the `iace-cloud-controls` catalog, never
  reused, and never renumbered.
- Rego v1 syntax only (`if`, `contains`, `in`, `every`). `opa fmt` is the formatter.
- Don't name variables or parameters after built-ins (`type_name`, `count`, `sum`, …): Regal's
  `var-shadows-builtin` flags it as a bug. Use `rtype` for a resource type. Keep lines ≤ 120
  characters by splitting long test inputs into local variables.

## Start from the templates
`assets/policies/` mirrors the repository's `policies/` directory. Copy it in T-0201
(`cp -r ${CLAUDE_SKILL_DIR}/assets/policies .` plus `assets/regal-config.yaml` → `.regal/config.yaml`).
- [imdsv2_required.rego](assets/policies/iace/rules/aws/ec2/imdsv2_required/imdsv2_required.rego)
  and its test show the metadata block, the violation shape, unknown handling, an absent-attribute
  default, and an account-level default resource that changes the verdict.
- [tf.rego](assets/policies/iace/lib/tf/tf.rego) and its test: `resources`, `data_sources`,
  `is_unknown`, `value_or`, `provider_major`, `referencing`.

These were verified with OPA 1.21.1 and Regal 0.43.0: `opa fmt`, `opa check --strict` with
restricted capabilities, `opa test` (18/18, 100% coverage), and `regal lint` (no violations).
Keep them passing when you change them.

## Metadata (package-scoped METADATA, required)
Full schema and severity rubric: [references/metadata-schema.md](references/metadata-schema.md).
The minimum: `title`, `description` (the *risk*, i.e. why it matters), `related_resources` (vendor
docs), and `custom.{id, severity, csp, service, resource_types, frameworks, remediation}`. The
engine refuses to load a rule with invalid metadata, and that is intended.

## The violation contract
```rego
deny contains violation if {
	some r in tf.resources("aws_instance")
	…conditions…
	violation := {
		"address": r.address,                       # must be a resource in input
		"attribute_path": ["metadata_options", 0, "http_tokens"],  # optional, sharpens the location
		"message": sprintf("%s allows IMDSv1: …", [r.address]),
	}
}
```
- **Messages** say what is wrong and what "right" looks like. Include the address and the
  expected setting. **Never interpolate attribute values** except known-safe enums or CIDRs
  (e.g. `"0.0.0.0/0"`, `"TLS1_0"`). Values can be secrets.
- One violation per (resource, distinct problem). For several bad entries in one resource (e.g.
  two open ports), emit one violation per entry with its own `attribute_path`.

## Semantics: the four traps
1. **Unknown is not a violation and not a pass.** Guard with `not tf.is_unknown(r, path)` for
   every path you judge. The engine reports unknown coverage separately.
2. **Absent is not false.** In HCL mode an omitted attribute means "the provider default". Use
   `tf.value_or(r, path, <default>)` and cite the provider doc and version in a comment.
3. **Defaults change across provider majors.** Branch on `tf.provider_major(r)`, and when the
   version is unknown (`-1`) assume the **oldest supported** major (the conservative choice).
   Real examples:
   - azurerm 5.0: `azurerm_storage_account.allow_nested_items_to_be_public` default changed
     true → false.
   - aws 6.0: `aws_redshift_cluster.publicly_accessible` default became false and `encrypted`
     default became true.
4. **Renamed attributes.** When supported provider majors span a rename, read both names
   (azurerm `enable_rbac_authorization` became `rbac_authorization_enabled`; 5.0 removed the old
   name). The `iace-cloud-controls` catalog records known renames.

Supported provider majors are defined in `iace-cloud-controls` (currently aws 5–6, azurerm 4–5).

## Cross-resource checks
Since AWS provider v4, many settings live in separate resources
(`aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`, …).
- Find related resources with `tf.referencing(type, attr, target)`, which matches the exact
  instance address or the base address.
- Also accept literal matches when references are absent (`bucket = "my-bucket"` equal to the
  bucket's `bucket` value), and treat an unknown linkage as unknown, not as missing.
- Account-level resources (e.g. `aws_s3_account_public_access_block`,
  `aws_ec2_instance_metadata_defaults`, `aws_ebs_encryption_by_default`) can satisfy a control
  for every resource in the configuration. Honour them only when present and known.
- Build lookup objects once (`pab_by_bucket := {…}`) instead of nested scans over all resources,
  which would be O(n²) on large repos.

## Tests (required for every rule)
In `<rule>_test.rego`, with synthetic resources built by a local helper function:
- [ ] one failing case **per distinct failing condition**, asserting the address and `attribute_path`
- [ ] at least one compliant case, plus the compliant-by-default case if the default is secure
- [ ] absent attribute, so the default semantics are pinned
- [ ] unknown value **and** unknown parent block, with no violation
- [ ] each provider-major branch, and the `-1` fallback
- [ ] `mode: data` and other resource types are ignored
- [ ] for list/collection rules: two bad entries produce two violations

Plus Terraform fixtures in `testdata/policies/<RULE-ID>/fail/` and `/pass/`. The Go harness
(`iace-testing`) proves that real HCL triggers the rule, and a CI job validates fixtures against
the real provider schemas, so a misspelled attribute fails somewhere.

## Tooling (all run by `make policy-check policy-test`)
```bash
opa fmt --list --fail policies
opa check --strict --capabilities policies/capabilities.json policies
regal lint policies
opa test --capabilities policies/capabilities.json --coverage --threshold 90 policies
```
Coverage targets: ≥ 90% per run (the gate), and aim for 100% on rule files. Uncovered lines in a
rule usually mean an untested branch, which is exactly where false negatives hide.

## Performance
- Start every rule with `some r in tf.resources("<type>")`, so it runs only over that type.
- No `walk(input)`, and no comprehensions over `input.resources` inside per-resource loops.
- Use `json.unmarshal` (IAM policies, for example) once per resource, then inspect the result.

## Lifecycle
- Changing a rule's semantics (new condition, different default) needs a changelog line in the
  PR description and updated tests that show the behaviour change.
- Deprecate with `custom.deprecated: true` and `custom.replaced_by: <ID>`. Deprecated rules still
  run for one minor release, with a report warning, and are then removed. IDs are never reused.
- Rule docs (`docs/rules/<ID>.md`) are **generated** from metadata (T-1104). Never hand-edit them.
