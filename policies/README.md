# iace policies

Built-in Rego (OPA v1) library and rules, embedded into the binary (`embed.go`). The layout
mirrors the packages: helpers in `iace/lib/<name>/` (`iace.lib.<name>`), rules in
`iace/rules/<csp>/<service>/<rule>/` (`iace.rules.<csp>.<service>.<rule>`), each file with a
`*_test.rego` beside it.

## Writing a rule
- Read resources only through `iace.lib.tf`: `tf.resources`, `tf.value_or`, `tf.is_unknown`,
  `tf.is_sensitive`, `tf.blocks`, `tf.referencing`.
- **Nested blocks: always `tf.blocks(r.values, "name")`** to iterate a block's entries, and paths
  such as `["metadata_options", 0, "http_tokens"]` with `tf.value_or` and `tf.is_unknown`. In
  `.tf.json`, a block written as one object stays an object (ADR 0006), so `r.values.x[0]`,
  `r.values.x[_]` or `some e in r.values.x` miss it. A test (`policies_test.go`) rejects rule
  files that read `values` that way.
- `tf.blocks` returns `[]` for an absent block and for an unknown one: check
  `not tf.is_unknown(r, ["name"])` before concluding that a block is missing, and guard each entry,
  `some i, b in tf.blocks(r.values, "name")` with `not tf.is_unknown(r, ["name", i, "attr"])`.
- Unknown is neither a violation nor a pass: guard every judged path with `not tf.is_unknown`.
- Absent means the provider default: `tf.value_or(r, path, default)`, with a comment citing the
  provider documentation and version; branch on `tf.provider_major(r)` where defaults changed.
- Messages never interpolate attribute values. Every rule ships with Rego tests and Terraform
  fixtures in `testdata/policies/<RULE-ID>/`:
  - `fail/` (HCL) and `fail_json/` (`.tf.json` only, nested blocks written as single objects),
    each with `expected.yaml` listing every finding's `address` and `attribute_path`;
  - `pass/`: compliant variants (explicit secure values, secure defaults, account-level settings);
  - `unknown/`: the judged value unknown inside a nested block, which must yield no finding.

  `internal/app/fixtures_test.go` scans each with the real loader and engine, and fails when a
  rule lacks a directory or a directory names no rule.

## Commands
- `make policy-check policy-test`: strict compile and tests (at least 90% coverage) with the
  restricted capabilities.
- `make lint`: Regal, with `.regal/config.yaml`.
- `make capabilities`: regenerate `capabilities.json` from the pinned OPA minus the denylist
  (network, host and non-deterministic builtins); review the diff.
