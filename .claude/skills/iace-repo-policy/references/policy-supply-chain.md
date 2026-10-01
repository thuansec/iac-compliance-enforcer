# Policy supply chain: bundles, signing, verification

Policies decide pass or fail for every scanned repository, so a tampered policy is as dangerous
as a tampered binary. Treat bundles like release artifacts: built in CI, signed, pinned by
digest, verified before use, and recorded in reports.

## Bundle layout (OPA bundle format)
```
.manifest            {"revision": "<git sha>", "roots": ["iace/rules/acme", "iace/lib/acme"],
                      "metadata": {"iace_source": "acme", "version": "1.4.0"}}
.signatures.json     JWT(s) over the file hashes, produced by `opa build --signing-key …`
iace/rules/acme/...  *.rego (no *_test.rego in published bundles)
iace/lib/acme/...    helpers
data.json            optional, under the declared roots only
```
- **Roots are the namespace boundary.** Built-in roots: `iace/lib/tf`, `iace/rules/aws`,
  `iace/rules/azure`, `iace/rules/gen`. Org bundles use `iace/rules/<org>` and `iace/lib/<org>`.
  iace checks root overlap itself (string-prefix check across all sources) and fails closed
  rather than relying on OPA activation behaviour.
- A central-library bundle (this repo's `policies/` at a tag) has the **same roots as builtin**.
  It is only valid with `builtin: false`, as a pinned replacement.

## Build and sign (this repo; T-0802)
```bash
# make policy-bundle VERSION=1.4.0   (CI only; the key never touches a laptop)
opa build --bundle policies/ \
  --ignore '*_test.rego' \
  --revision "$(git rev-parse HEAD)" \
  --signing-alg ES256 --signing-key "$POLICY_SIGNING_KEY_FILE" \
  --output dist/iace-policies-1.4.0.tar.gz
sha256sum dist/iace-policies-1.4.0.tar.gz > dist/iace-policies-1.4.0.tar.gz.sha256
```
Check the exact `opa build` flags (`--ignore`, `--signing-*`, `--scope`, `--claims-file`) against
the pinned OPA version's `opa build --help` before scripting. They were verified present in 1.15.
- Key: ES256 (P-256). The private key lives in a GitHub Actions **environment** secret
  (`policy-release`, with required reviewers) or follows whatever D-03 decides. The public key,
  with its `key_id` (e.g. `iace-policies-2026`), is embedded in the iace binary's trust store.
- The release workflow uploads the bundle and its `.sha256` as release assets, and links them in
  the release notes with the exact `.iace.yaml` snippet to pin it.
- Rotation: generate the new key, ship a binary that trusts both key IDs, switch signing,
  and remove the old key two releases later. Revocation = a binary release that removes the key ID.

## Verify and load (iace; T-0803)
Order matters: integrity first, then authenticity, then content checks.
1. **Fetch** (HTTPS only; hosts must be in `allowed_source_hosts`, default `github.com`,
   `api.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` (verify the current
   GitHub asset host)). Use a 60 s timeout, at most 5 redirects (each to an allowlisted host), and
   cap the body at 50 MiB with `io.LimitReader`. Never send credentials to a host other than the
   one they are for: set Authorization only for `api.github.com`, and strip it on every redirect
   in `CheckRedirect`.
   - Private repositories: use the API asset endpoint
     `GET https://api.github.com/repos/<owner>/<repo>/releases/assets/<id>` with
     `Accept: application/octet-stream` and a token from `GITHUB_TOKEN`/`IACE_SOURCE_TOKEN`
     (CI-provided).
2. **Digest**: sha256 of the downloaded bytes must equal the pin. Compare as fixed-length lowercase hex.
3. **Signature**: read with `bundle.NewReader(...)` configured with a verification config (keys
   from the trust store, the expected `key_id`, and an optional scope). Verify the exact
   constructor names in the pinned OPA `v1/bundle` package. A missing `.signatures.json`, an
   unknown key ID, a bad signature, or a file not covered by the signature are all errors.
4. **Content**: only `.rego`, `data.json`/`data.yaml` and the manifest are allowed. Reject
   absolute paths, `..`, symlinks or hardlinks in the tar, more than 5,000 files, more than 200 MiB
   uncompressed, and roots outside the namespace rules.
5. **Compile** with the same capabilities and strict mode as built-ins, then validate metadata
   (rule-ID prefix rules: external bundles cannot use `IACE-`).

## Trust store
- Embedded: official iace policy keys (`internal/policy/trust/*.pem`, with key IDs in file names).
- Additional keys come **only** from trusted inputs: `--trusted-key id=path`, `IACE_TRUSTED_KEYS`
  (JSON or a list of `id=path`), or the org baseline's `trusted_keys`. Never from `.iace.yaml`,
  because a PR author could otherwise add their own key next to their own bundle.

## Cache and offline
- Content-addressed: `$IACE_CACHE_DIR/bundles/<sha256>.tar.gz`, directory 0700, files 0600.
- Re-verify the digest **and** signature on every load. A cache is a performance feature, not a trust anchor.
- `--offline`: never touch the network. A missing cache entry is an error that names the source and
  gives the command to prefetch it (`iace policy fetch`).

## Git sources (optional, T-0807 if ever needed)
Only by full 40-hex commit SHA (tags and branches move), fetched with `git` using explicit args,
no shell, `GIT_TERMINAL_PROMPT=0`, a timeout and a depth-1 fetch. Content checks as above.
Signatures are not applicable unless commit signing is verified. Prefer bundles.
