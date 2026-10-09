# 0013 · Resolve remote modules only through the module manifest

- Status: accepted
- Date: 2026-10-09
- Task: T-0107d
- Extends: ADR 0008

## Context
Registry, git and http module sources point at code that iace never downloads (ADR 0003).
When a pipeline has already run `terraform init`, the modules sit in `.terraform/modules`, and
`.terraform/modules/modules.json` maps each module key (the dot-joined call names from the root)
to a source, a version and a directory. In a pull request, that file and those directories are
untrusted: the author can commit them, point a key at any directory, or leave a stale entry
for a source that has since changed.

## Decision
- Manifest resolution is off by default. It is enabled only by a trusted input
  (`TreeOptions.TrustModuleManifest`, wired to a CLI flag or environment variable of the
  pipeline in T-0109), never by `.iace.yaml` or anything else in the scanned repository.
  Without it, the manifest is not even read, and remote calls stay unresolved (remote_source).
  `terraform init` does not replace a committed `.terraform`: it reuses an installed module
  whose manifest record matches the call's source and version, and fetches again only with
  `-upgrade`. So a manifest that a pull request committed cannot be trusted just because the
  pipeline also ran init.
- When trusted, the manifest is read from the root module's directory only, through the scan
  root:
  - capped at 1 MiB and 10,000 entries;
  - one JSON value with no trailing data;
  - no duplicate keys.
- A manifest that breaks any of these rules is ignored as a whole, with a
  module_manifest_invalid warning. Unknown fields are allowed, so newer Terraform versions keep
  working.
- A remote source resolves per call, by its key (`a.b`), because one directory can appear under
  several keys. The entry's Source must equal the call's source, or `registry.terraform.io/`
  followed by it; otherwise the call is unresolved as stale_manifest. Terraform stores other
  shorthand (`github.com/org/repo`, `git@github.com:...`) in a normalized git form that iace does
  not derive, so such calls are stale_manifest too. That fails closed, at the cost of
  coverage.
- The entry's Dir is relative to the root module's directory. Empty, absolute and Windows
  volume paths are refused, and the result must be a directory inside the scan root reached
  without symlinks (the same check as local sources, ADR 0008).
- Without a usable entry, a remote call stays unresolved with its warning, which T-0109 maps to
  an unresolved_module gap.
- Version constraints are not checked against the manifest's Version.

## Alternatives considered
- Trust any manifest found in the scan root: a pull request could commit a manifest and a
  benign copy of a module, under a matching source such as its own `git::` URL. A call that was
  an unresolved_module gap would then look checked, passing `--fail-on-gaps`. That is verdict
  tampering (threat model T4).
- Trust the manifest's Dir without checking the source: a forged or stale entry could map a call
  to other code.
- Resolve remote modules by convention (`.terraform/modules/<name>`) without a manifest: keys
  of nested calls are ambiguous, and nothing ties the directory to the source.

## Consequences
- Positive: pipelines that prepare `.terraform` in a trusted step get remote modules checked,
  with the same confinement as local ones. By default, a repository cannot turn an unresolved
  module into a checked one.
- Negative / accepted risks:
  - Trusting the manifest is only safe when a trusted step removed any committed `.terraform`
    (or ran `terraform init -upgrade` in a clean checkout) before the scan. This is documented
    with the option in T-0109, and with the CI guidance in M10.
  - Shorthand git sources are not resolved yet.
