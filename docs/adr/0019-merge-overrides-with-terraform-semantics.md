# 0019 · Merge overrides with Terraform semantics

- Status: accepted
- Date: 2026-10-09
- Tasks: T-0112a; T-0112b (resources and data sources)

## Context
ADR 0005 reported override files (`override.tf`, `*_override.tf` and their `.tf.json` forms)
instead of merging them, so an override could change a value and the scan only showed a gap.
Terraform loads every other file of a module first, then applies the override files in name
order, and the blocks of each file in source order, to the blocks they name. An override that
names a block no other file declares makes Terraform reject the module.

Resource and data bodies are read by the resource decoder, which depends on the concrete HCL or
JSON body for its cost, structure, dynamic-block and reference accounting. Every other block is
read through the generic `hcl.Body` interface.

## Decision
- ParseModule sets aside the blocks of override files and merges them after every other file
  (applyOverrides), in file name order, then source order.
- variable, output, module and provider blocks merge into the block of the same type and name. A
  provider is named by its name and its `alias`. The merged body (mergedBody) works as follows:
  - An override attribute replaces the base attribute of the same name.
  - Override nested blocks of a type replace all base nested blocks of that type.
  - Neither side alone must hold a required attribute. The merged content must.
- locals merge by name. The base value is hidden (maskedBody), and the override's value is
  declared in its place.
- terraform settings merge into the module's settings. What the override sets is hidden in every
  base terraform block, and the override block is added after them.
  - Attributes (`required_version`, ...) and nested block types replace the base's.
  - `backend` and `cloud` replace each other.
  - `required_providers` merges by provider name.
- An override of a variable, output, module call, provider or local value with no base is an
  error, `override_without_base`, as Terraform rejects the module. That override is not used.
- `depends_on` in a module or output override is an error, `override_unsupported`, as in
  Terraform.
- A local value declared twice in the module's own files is left as it is. declareLocals reports
  the duplicate where it is, and an override of it is not used.
- Merging is linear in the override blocks, because override files are untrusted and a 1 MiB file
  holds tens of thousands of blocks:
  - Block identities, local owners and terraform settings are indexed once.
  - Masks and override lists accumulate, and each body is wrapped once, at the end.
  - The context is checked between override blocks.
  - A test parses 1 MiB of overrides of one local, setting, provider and variable.
- A merged block holds expressions from more than one file. So whether an expression is JSON is
  decided by the expression's own file (inJSON), not the block's file.
- resource and data overrides (T-0112b) are layered over the block of the same type and name,
  which must exist (`override_without_base`). The resource decoder merges the layers
  (overriddenBody) by the same rules, for HCL and JSON bodies alike:
  - At the top of the body, a layer skips every attribute and nested block type, static or
    dynamic, that a later layer sets. A replaced value is never evaluated, recorded or
    referenced. The last layer that sets each name is indexed once, so decoding stays linear.
  - Meta-arguments apply layer by layer: count, for_each and provider replace, and so does each
    lifecycle argument. An `ignore_changes` list replaces the one before only when it is not
    empty, and `ignore_changes = all`, once set, stays, as in Terraform.
  - depends_on in a resource or data override is an error (`override_unsupported`), as for
    module calls and outputs.
  - Cost and structure are charged for every layer, which can only over-count.
- moved, import and removed blocks in an override file are errors (`override_unsupported`), as
  Terraform rejects them. ephemeral, check and action blocks are not checked by iace in any file,
  so their overrides change nothing iace checks.
- `override_not_merged` and ADR 0005's accepted risk are retired.

## Alternatives considered
- A merged hcl.Body for resources: the resource decoder reads concrete HCL and JSON bodies for
  its cost, structure, dynamic-block and reference accounting, so it layers the bodies instead.
- Rewrite override bodies into new syntax trees: it would lose source ranges, which findings
  and diagnostics point to.

## Consequences
- Positive: an override that redirects a module source, changes a variable default or a local
  value, or changes provider requirements is checked as Terraform would apply it. An override
  without a base fails closed, because the module has errors.
- Negative / accepted risks: Terraform's rule that a variable's `type` set only in an override re-converts the
  base default is not modelled: the default is converted to the merged type.
