# Policy supply chain: bundles, signing, verification

Policies decide pass or fail for every scanned repository, so a tampered policy is as dangerous
as a tampered binary. Treat bundles like release artifacts: built in CI, signed, pinned by
digest, verified before use, and recorded in reports.

## Bundle layout (OPA bundle format)
```
.manifest            {"revision": "<git sha>", "roots": ["iace/rules/acme", "iace/lib/acme"],
                      "metadata": {"iace_source": "acme", "version": "1.4.0"}}
iace/rules/acme/...  *.rego (no *_test.rego in published bundles)
iace/lib/acme/...    helpers
data.json            optional, under the declared roots only
```
The signature is detached: `<bundle>.tar.gz.sig` is published next to the bundle and covers the
whole tarball, so the bundle carries no `.signatures.json`.
- **Roots are the namespace boundary.** Built-in roots: `iace/lib/tf`, `iace/rules/aws`,
  `iace/rules/azure`, `iace/rules/gen`. Org bundles use `iace/rules/<org>` and `iace/lib/<org>`.
  iace checks root overlap itself (string-prefix check across all sources) and fails closed
  rather than relying on OPA activation behaviour.
- A central-library bundle (this repo's `policies/` at a tag) has the **same roots as builtin**.
  It is only valid with `builtin: false`, as a pinned replacement.

## Build and sign (this repo; T-0802)
The signing key is an AWS KMS key (decision D-03): key spec `ECC_NIST_P256`, key usage
`SIGN_VERIFY`. Its private half never leaves KMS. `opa build` can only sign with a local key
file, so the bundle is built unsigned and then signed as a whole, in CI only:
```bash
# make policy-bundle VERSION=1.4.0   (build and hash; needs no key)
opa build --bundle policies/ \
  --ignore '*_test.rego' \
  --revision "$(git rev-parse HEAD)" \
  --output dist/iace-policies-1.4.0.tar.gz
sha256sum dist/iace-policies-1.4.0.tar.gz > dist/iace-policies-1.4.0.tar.gz.sha256

# policy-release.yml only, after assuming the signing role through GitHub OIDC
openssl dgst -sha256 -binary dist/iace-policies-1.4.0.tar.gz > dist/digest.bin
aws kms sign --key-id "$POLICY_SIGNING_KEY_ARN" --message fileb://dist/digest.bin \
  --message-type DIGEST --signing-algorithm ECDSA_SHA_256 \
  --query Signature --output text > dist/iace-policies-1.4.0.tar.gz.sig
```
Check the exact `opa build` and `aws kms sign` flags against the pinned versions before scripting.
`DIGEST` is required: KMS signs raw messages only up to 4096 bytes.
- Signature format: `<bundle>.sig` holds the base64 of a DER-encoded ECDSA P-256 signature over
  the tarball's SHA-256, which is what KMS returns. Anyone can check it with the public key, e.g.
  `openssl dgst -sha256 -verify iace-policies-2026.pem -signature <(base64 -d x.sig) x.tar.gz`.
  Org bundles use the same format with their own P-256 key (KMS, an HSM or openssl).
- Who can sign: only policy-release.yml running for a `policies-v*` tag. Its IAM role trusts
  GitHub OIDC tokens with `aud` `sts.amazonaws.com` and `sub`
  `repo:thuansec/iac-compliance-enforcer:ref:refs/tags/policies-v*`, and may only call `kms:Sign`
  and `kms:GetPublicKey` on that key. Branch workflows, including the loop's, cannot assume it.
  Anyone with write access can create a `policies-v*` tag and so trigger signing, so keep write
  access to the owner; the loop never pushes tags. The release-tag ruleset
  (`docs/ci/tags-ruleset.json`) stops a signed tag from being moved or deleted.
- The workflow verifies the new signature with the embedded public key before uploading, and
  fails closed if it does not verify.
- The public key (`aws kms get-public-key`, converted to PEM), with its `key_id` (e.g.
  `iace-policies-2026`), is embedded in the iace binary's trust store (T-0808).
- The release workflow uploads the bundle, its `.sig` and its `.sha256` as release assets, and
  links them in the release notes with the exact `.iace.yaml` snippet to pin it.
- Rotation: KMS does not rotate asymmetric keys automatically. Create a new KMS key with a new
  `key_id`, ship a binary that trusts both key IDs, switch signing, and remove the old key two
  releases later. Revocation = a binary release that removes the key ID, plus disabling the KMS key.

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
3. **Signature**: fetch `<url>.sig` (or `<path>.sig`) under the same rules, capped at 1 KiB. Look
   up the source's `key_id` in the trust store (P-256 public keys only), base64-decode the
   signature and check `ecdsa.VerifyASN1(pub, sha256(bundle), sig)` **before** the tarball is
   parsed. A missing or malformed `.sig`, an unknown key ID, a key that is not P-256, or a bad
   signature are all errors.
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
