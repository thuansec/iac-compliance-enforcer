#!/usr/bin/env bash
# Run the scan step of the iace GitHub Action from the repository root (the working directory).
#
# Environment: IACE_BIN (the iace binary), IACE_PATHS (directories to scan, separated by any
# whitespace including newlines), IACE_SARIF (the SARIF path, relative to the repository root)
# and GITHUB_OUTPUT. Sets the outputs exit-code (iace's exit code) and upload=true when the SARIF
# holds a complete analysis (exit code 0 or 1). A refused input sets neither: iace did not run,
# so the later steps report that and fail with exit code 2 without reading any SARIF.
#
# The workspace is a checked-out pull request: the SARIF path must not lead through a symlink,
# or a PR could make the action overwrite a file outside the workspace (ADR 0053).
set -euo pipefail

refuse() {
  echo "::error title=iace::$*"
  exit 0
}

paths=()
read -r -d '' -a paths <<<"$IACE_PATHS" || true
if [[ ${#paths[@]} -eq 0 ]]; then paths=(.); fi
# Until T-0302b, one PATH other than the root makes SARIF URIs relative to that PATH, which code
# scanning cannot place; refuse rather than upload misplaced alerts. "infra ./infra/" is one path.
declare -A distinct=()
for p in "${paths[@]}"; do
  while [[ "$p" == ./?* ]]; do p="${p#./}"; done
  while [[ "$p" == ?*/ ]]; do p="${p%/}"; done
  distinct["$p"]=1
done
if [[ ${#distinct[@]} -eq 1 && -z "${distinct[.]:-}" ]]; then
  refuse "path: a single directory other than . is not supported yet; scan . or list several directories"
fi

case "/$IACE_SARIF/" in
  //* | */../* | *//) refuse "sarif-file must be a relative path inside the repository without .." ;;
esac
dir="$(dirname -- "$IACE_SARIF")"
prefix=""
IFS=/ read -r -a parts <<<"$dir"
for part in "${parts[@]}"; do
  [[ -z "$part" || "$part" == "." ]] && continue
  prefix="${prefix:+$prefix/}$part"
  if [[ -L "$prefix" ]]; then refuse "sarif-file: $prefix is a symlink"; fi
done
mkdir -p -- "$dir"
rm -f -- "$IACE_SARIF" || refuse "sarif-file: $IACE_SARIF cannot be replaced"

set -o noclobber
set +e
"$IACE_BIN" scan -o sarif -- "${paths[@]}" >"$IACE_SARIF"
code=$?
set -e
echo "exit-code=$code" >>"$GITHUB_OUTPUT"
if [[ ($code -eq 0 || $code -eq 1) && -s "$IACE_SARIF" ]]; then
  echo "upload=true" >>"$GITHUB_OUTPUT"
fi
