---
name: iace-repo-policy
description: Repository policy for iace — the per-repo `.iace.yaml` (policy selection, severity thresholds, accountable exceptions with owner/reason/expiry, disabled rules, rule parameters, path exclusions, AI settings), the org baseline that repositories may only tighten, and policy sources (built-in embedded policies plus central/org OPA bundles from github.com/thuansec/iac-compliance-enforcer releases, pinned by sha256 and signature-verified). Use this for any work in internal/config, internal/exceptions or internal/policy; when designing or validating config keys; implementing exception expiry; building, signing, publishing, caching or verifying policy bundles; or answering "how does a repo opt out / pin policies / record an exception".
---

# Repo policies: config, exceptions, policy sources

## Who controls what
| layer | controlled by | can |
|---|---|---|
| built-in policies | iace releases (this repo's `policies/`) | define rules; embedded in the binary |
| central and org bundles | this repo's policy releases, or an org's policy repo | add rules, or replace the built-ins with a pinned library version |
| org baseline (`--org-config`) | the security team, supplied by trusted CI | set mandatory rules, a minimum `fail_on`, exception limits, required sources, trusted keys |
| repo config (`.iace.yaml`) | repository maintainers (CODEOWNERS-reviewed) | select policies, **tighten** thresholds, record exceptions within limits |
| CLI flags | the person or pipeline running iace | override for local runs; in CI they come from the trusted workflow |

**Repo config is attacker-reachable**: any PR author can edit it. So it can never add trusted
keys, disable mandatory rules, loosen the org minimum, or point at unpinned sources. Recommend
`CODEOWNERS: /.iace.yaml @security-team` in every scanned repo, so new exceptions get reviewed.

## `.iace.yaml` v1
The full spec, an example and validation rules are in
[references/config-schema.md](references/config-schema.md). The JSON Schema is
`schemas/config.v1.json`, and the loader must match it exactly.
- **Strict loading**: `go.yaml.in/yaml/v3` with `KnownFields(true)`. An unknown key is an error
  citing file:line (typos like `expiry:` must not silently drop an exception's expiry). Then
  JSON Schema validation, then semantic validation (dates, ID patterns, digests, globs).
- **Discovery**: `--config` / `IACE_CONFIG`, then `<scan root>/.iace.yaml` (or `.yml`), then the
  git toplevel. A missing config means defaults; a config that fails to parse means exit 2.
- **Size and safety**: 1 MiB limit, no YAML anchors or merge keys (they hide content from
  reviewers), and at most 1,000 exceptions.

## Exceptions (accountable, expiring)
An exception says: "this rule may fail on these resources, because <reason>, owned by
<owner>, until <date>".
- Required: `id` (unique, `EXC-…`), `rules` (explicit IDs, no wildcards), `resources` (address
  globs; at least one; `*`/`**` alone is rejected), `reason` (≥ 15 chars), `owner` (email or
  GitHub `@user`/`@org/team`), `expires` (ISO date). Optional: `paths` (file globs), `ticket`, `created`.
- `expires` must be ≤ today + `max_exception_days` (default 180; the org baseline may lower it).
  Today comes from the injected clock.
- **Matching**: a finding is `excepted` when its rule ID is listed, its resource address matches a
  glob (path.Match semantics per address segment, `**` for module depth), and its file matches
  `paths` when given.
- **Lifecycle warnings** (shown in every report format):
  - expired: the exception no longer applies, so the finding is open and can block. Warning `EXC-… expired on …`.
  - expiring within 14 days: warning.
  - stale (matched no finding in this scan): warning, so dead exceptions get cleaned up.
- Excepted findings stay visible: JSON `status: excepted`, SARIF `suppressions` (`kind: external`,
  justification = reason), and a separate count in text and Markdown. They never count toward `fail_on`.
- `disabled_rules` work the same way (owner, reason and expiry required) but switch a rule off for
  the whole repository. They cannot target org-mandatory rules.

## Org baseline (`--org-config`, M4/T-0407)
Supplied by the trusted CI workflow (a checked-in file in the central repo, or one fetched as a
pinned asset), never discovered from the scanned repo. Fields: `mandatory_rules`,
`non_exceptionable_rules`, `minimum_fail_on`, `max_exception_days`, `required_sources`,
`trusted_keys`, `allowed_source_hosts`, `builtin_policies: required`.
Merge rule: **repo config may only tighten**. Any attempt to loosen is a `ConfigError` (exit 2)
naming the field. A quiet override would let a PR switch enforcement off.

## Policy sources (M8)
Supply-chain design (bundle layout, manifest roots, signing, verification, cache, private
GitHub downloads, key rotation): [references/policy-supply-chain.md](references/policy-supply-chain.md).

Summary:
- **builtin**: `policies/` embedded via go:embed. Roots: `iace/lib/tf`, `iace/rules/aws`,
  `iace/rules/azure`, `iace/rules/gen`. It needs no verification beyond the signed binary.
- **central library pin**: a signed bundle of this repo's `policies/` at a release tag. Loading it
  *replaces* the built-in library (same roots) to decouple policy updates from binary upgrades.
  Requires `builtin_policies: false`. Otherwise the roots overlap and loading fails.
- **org/team bundles**: additional rules **alongside** the built-ins, under their own roots
  (`iace/rules/<org>/…`, `iace/lib/<org>/…`) and their own rule-ID prefix (not `IACE-`).
- Every non-builtin source must have a **sha256 pin** and a **valid signature** from a key in
  the trust store. Overlapping roots or duplicate rule IDs across sources are errors naming both.
  There is no "first wins" behaviour.
- Reports record each source's name, version and digest, and each finding names its source (T-0805).

## Tests that must exist
- config: unknown key → error with line; a YAML anchor → error; each required exception field missing → error
- exceptions: match/no-match tables; expired/expiring/stale with a fixed clock; `**` address globs; SARIF suppressions
- org baseline: each loosening attempt → ConfigError; tightening accepted
- sources: tampered bundle, wrong digest, wrong key, unknown key ID, missing signature, oversized
  archive, path traversal entry, overlapping roots, duplicate rule ID, `--offline` with an empty cache
