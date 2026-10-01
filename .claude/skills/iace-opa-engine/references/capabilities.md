# Restricted capabilities

## Denylist
Removed from `opa capabilities --current` of the pinned OPA version:

| builtin | why |
|---|---|
| `http.send` | network access from policies; also a data-exfiltration channel |
| `net.*` (e.g. `net.lookup_ip_addr`) | DNS/network access |
| `opa.runtime` | leaks environment and config; makes results host-dependent |
| `time.now_ns` | non-deterministic; policies judge configuration, not wall-clock time |
| `rand.intn` | non-deterministic |
| `uuid.rfc4122` | non-deterministic |

Also set `"allow_net": []`, which stops any remaining network-capable builtin from reaching any host.

Kept on purpose: `print` and `trace` (compiled out in production, and blocked from commits by
Regal), plus all deterministic builtins, including `json.*`, `regex.*`, `net.cidr_*` (pure CIDR
math, not network access, despite the prefix; see below), `time.parse_*` and `crypto.*`.

**Careful with the `net.` prefix:** `net.cidr_contains`, `net.cidr_intersects`, `net.cidr_merge`
and similar are pure functions that SG/NSG rules need. Deny only network-performing builtins
(`net.lookup_ip_addr`), and list them explicitly rather than by prefix.

## Generation (Makefile target `capabilities`)
Generate, don't hand-edit. A small Go program (`internal/engine/capgen`, run via `go run`) or a
script:
1. Runs `opa capabilities --current` using the pinned OPA (`go tool -modfile=tools/go.mod opa`).
2. Removes the denylisted builtins by exact name.
3. Sets `allow_net` to `[]`.
4. Writes `policies/capabilities.json` with sorted keys, so the diff is reviewable.

This snapshot is also an allowlist going forward: builtins added by later OPA releases are absent
until someone regenerates the file and reviews the diff.

Verified recipe (Python, as run during skill authoring against OPA 1.15.1 and 1.21.1):
```python
import json
caps = json.load(open("caps-full.json"))            # from: opa capabilities --current
deny = {"http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns", "rand.intn", "uuid.rfc4122"}
caps["builtins"] = [b for b in caps["builtins"] if b["name"] not in deny]
caps["allow_net"] = []
json.dump(caps, open("policies/capabilities.json", "w"), indent=1, sort_keys=True)
```
Result: compliant policies pass `opa check --strict --capabilities policies/capabilities.json`,
and a policy calling `http.send` fails with `rego_type_error: undefined function http.send`.

## Tests
- `TestCapabilitiesDenylist`: load the embedded capabilities.json and assert that no denylisted
  builtin is present and that `allow_net` is empty.
- `TestCapabilitiesMatchPinnedOPA`: regenerate in memory from the linked OPA library version and
  diff it against the committed file. This fails when OPA was bumped without `make capabilities`.
- Engine test: compiling a module that calls `http.send` returns a `PolicyError`.
