# 0048 · Locate overridden attributes in their own file

- Status: accepted
- Date: 2026-10-18
- Task: T-0134
- Amends: ADR 0004 (input document v1, `source`)

## Context
Override files (`*_override.tf`, `override.tf`) merge their attributes into the base block, as
Terraform does. The input document recorded one `source.file` per resource (the base file) and a
range per attribute in `source.attributes`. An attribute the override set kept the override's
range but not its file, so in the override fixture `acl = "public-read"`, set at
main_override.tf:3, pointed at main.tf:3 instead. A finding on a weakening override, which is
the case the threat model's T14 row cares about, would have named the wrong file and line.

Options:
- (a) Record the file of every attribute set outside `source.file`, in a new optional map.
- (b) Drop those attributes from `source.attributes`, so findings fall back to the block range.
  That points at the base block, still not at the override that weakened it.
- (c) Make each `source.attributes` entry a location with its own file. That is a rename of the
  value shape: a breaking change needing input document v2.

## Decision
Option (a). `source.attribute_files` maps the dot-joined path of each attribute set in another
file than `source.file` to that file, relative to the scan root. It is omitted when every
attribute is in `source.file`, so documents without overrides are unchanged. An attribute's
location is `attribute_files[path]` (else `source.file`) with `attributes[path]`. The block
range stays the base block's.

## Consequences
- Additive: schema `input.v1.json` gains the optional property (at least one entry when
  present); existing consumers and goldens without overrides are unchanged.
- Reporters (M3) and finding construction (T-0204) must read `attribute_files` before
  `source.file` when they locate an attribute.
- The input-document reference in the iace-architecture skill lives in the harness; its update
  joins T-0110b for the owner.
