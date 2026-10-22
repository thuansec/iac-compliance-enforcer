#!/usr/bin/env bash
# Install a released iace binary for the iace GitHub Action (release-binary mode).
#
# Usage: install-release.sh VERSION DEST_DIR
#
# Downloads iace_<version>_<os>_<arch>.tar.gz and checksums.txt from the GitHub release vVERSION,
# checks the archive's sha256 against checksums.txt and extracts only the iace binary into
# DEST_DIR. Any mismatch, missing entry or download error fails before anything is installed.
# The asset names follow the GoReleaser config of T-1101; the attestation check
# (gh attestation verify) joins once releases are signed (M11).
#
# IACE_RELEASE_ASSETS names a local directory that already holds the release assets (an
# air-gapped mirror, or the tests); nothing is downloaded then, and the checksum check still runs.
set -euo pipefail

readonly REPO_URL="https://github.com/thuansec/iac-compliance-enforcer/releases/download"

fail() {
  echo "install-release: $*" >&2
  exit 1
}

[[ $# -eq 2 ]] || fail "usage: install-release.sh VERSION DEST_DIR"
version="${1#v}"
dest="$2"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
  fail "version \"$1\" is not a release version such as v1.2.3"

os="${RUNNER_OS:-$(uname -s)}"
case "$os" in
  Linux | linux) os=linux ;;
  macOS | Darwin | darwin) os=darwin ;;
  *) fail "release-binary mode supports Linux and macOS runners, not $os; leave version empty to build from source" ;;
esac
arch="${RUNNER_ARCH:-$(uname -m)}"
case "$arch" in
  X64 | x86_64 | amd64) arch=amd64 ;;
  ARM64 | arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported runner architecture $arch" ;;
esac

archive="iace_${version}_${os}_${arch}.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -n "${IACE_RELEASE_ASSETS:-}" ]]; then
  cp -- "$IACE_RELEASE_ASSETS/$archive" "$IACE_RELEASE_ASSETS/checksums.txt" "$work/" ||
    fail "release assets for v$version are missing from $IACE_RELEASE_ASSETS"
else
  for asset in "$archive" checksums.txt; do
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
      --output "$work/$asset" "$REPO_URL/v$version/$asset" ||
      fail "could not download $asset of v$version"
  done
fi

want="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$work/checksums.txt")"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || fail "checksums.txt has no single sha256 checksum for $archive"
if command -v sha256sum >/dev/null; then
  got="$(sha256sum "$work/$archive" | awk '{ print $1 }')"
else
  got="$(shasum -a 256 "$work/$archive" | awk '{ print $1 }')"
fi
[[ "$got" == "$want" ]] || fail "checksum mismatch for $archive: got $got, want $want"

mkdir -p "$work/x"
tar -xzf "$work/$archive" -C "$work/x" iace || fail "$archive holds no iace binary"
[[ -f "$work/x/iace" && ! -L "$work/x/iace" ]] || fail "$archive holds no regular iace binary"
mkdir -p "$dest"
install -m 0755 "$work/x/iace" "$dest/iace"
echo "install-release: installed iace v$version ($os/$arch, sha256 $got)"
