---
paths:
  - "policies/**"
  - "testdata/policies/**"
---

# Rego policies: the four traps

Load the `iace-rego-policies` and `iace-cloud-controls` skills before changing a rule. Every
rule must get these right:

1. **Unknown is neither a violation nor a pass.** Guard every judged path with `not tf.is_unknown(r, path)`.
2. **Absent means the provider default.** Use `tf.value_or(r, path, default)`, with a comment
   citing the provider doc and version.
3. **Defaults change across provider majors** (aws 5–6, azurerm 4–5). Branch on
   `tf.provider_major(r)`, and treat `-1` as the oldest supported major.
4. **Renamed attributes:** read both names while the supported majors span the rename.

Verify attribute names and defaults with `iace-cloud-controls/scripts/provider_schema.sh`, not
from memory. Messages never interpolate attribute values. Every rule needs pass/fail fixtures
plus Rego tests (≥ 90% coverage), and `regal lint` must be clean.
