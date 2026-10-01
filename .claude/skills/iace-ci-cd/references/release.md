# Releases (M11) and policy-bundle publishing (M8)

## Versioning
- The CLI uses SemVer tags `vX.Y.Z`. Breaking changes to CLI flags, exit codes, output schemas or
  config schema bump the major (pre-1.0: the minor).
- Policy bundles are versioned independently with tags `policies-vX.Y.Z`. Rule semantics changes
  bump the minor, and new rules bump the minor.
- The changelog is generated from Conventional Commits (feat → minor, fix → patch, `!` → breaking).

## GoReleaser (`.goreleaser.yaml`)
- builds: `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -X …/internal/version.Version={{.Version}} -X ….Commit={{.FullCommit}} -X ….Date={{.CommitDate}}"`,
  `mod_timestamp: "{{ .CommitTimestamp }}"` for reproducibility; goos linux/darwin/windows, goarch amd64/arm64.
- archives with LICENSE and README, plus `checksums.txt` (sha256).
- `sboms`: SPDX or CycloneDX via syft, per archive.
- `signs`: cosign keyless (`cosign sign-blob --yes --bundle=…`), using the workflow's OIDC token (`id-token: write`).
- Local check: `goreleaser release --snapshot --clean` must pass (T-1101). It needs no credentials.

## release.yml (tag push `v*`)
```
permissions: contents: write (release), id-token: write (cosign/attestations), attestations: write
steps: checkout (pinned) → setup-go (go-version-file) → make ci → goreleaser (pinned action)
       → actions/attest-build-provenance (pinned) for the archives and checksums.txt
```
Consumers verify with `gh attestation verify <file> --repo thuansec/iac-compliance-enforcer`
and/or `cosign verify-blob`. The composite action does this in release-binary mode.

## policy-release.yml (tag push `policies-v*`)
- Runs in the protected environment `policy-release` (required reviewers). The signing key is
  an environment secret (D-03).
- Steps: `make policy-check policy-test`, then `make policy-bundle VERSION=…` (signed ES256,
  see iace-repo-policy), then sha256, then upload the bundle and checksum as release assets, then
  build-provenance attestation for the bundle.
- The release notes include the pin snippet:
  ```yaml
  sources:
    - name: iace-central
      url: https://github.com/thuansec/iac-compliance-enforcer/releases/download/policies-v1.4.0/iace-policies-1.4.0.tar.gz
      sha256: <digest>
      key_id: iace-policies-2026
  ```

## Release checklist (T-1106, human-owned)
- [ ] Decision D-01 (license) resolved; LICENSE file present
- [ ] `make ci` green on main; fixtures workflow green
- [ ] CHANGELOG reviewed; docs/rules regenerated
- [ ] threat model reviewed (T-1105)
- [ ] tag pushed by a human; release workflow green; attestation verifies
- [ ] action release-binary mode tested against the new release
