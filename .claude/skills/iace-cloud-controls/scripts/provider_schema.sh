#!/usr/bin/env bash
# Verify Terraform provider attribute names and defaults before writing a policy.
#
#   provider_schema.sh schema <provider> <version> [resource_type]
#       Downloads the provider (official registry) into a throwaway config we generate,
#       dumps `terraform providers schema -json` (cached), and optionally prints one
#       resource's attributes and nested blocks (type, required/optional/computed,
#       sensitive, deprecated). Schemas do NOT contain defaults: use `docs` for those.
#
#   provider_schema.sh docs <aws|azurerm> <version> <resource_type> [attribute]
#       Fetches the resource's registry doc page source for that exact provider tag
#       (cached) and prints the lines mentioning the attribute (defaults, allowed values).
#
# <provider> is a short hashicorp name (aws, azurerm, random) or namespace/name.
# Needs network and terraform. This runs `terraform init` only on a config generated here,
# never on scanned code. Cache: ${IACE_CACHE_DIR:-<repo>/.cache}/provider-schemas
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[[ $# -ge 3 ]] || usage

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CACHE="${IACE_CACHE_DIR:-$ROOT/.cache}/provider-schemas"
mkdir -p "$CACHE"

mode="$1" provider="$2" version="$3"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be exact (e.g. 6.12.0)" >&2; exit 2; }
if [[ "$provider" == */* ]]; then ns="${provider%%/*}" name="${provider##*/}"; else ns="hashicorp" name="$provider"; fi
[[ "$ns/$name" =~ ^[a-z0-9-]+/[a-z0-9-]+$ ]] || { echo "invalid provider '$provider'" >&2; exit 2; }

case "$mode" in
schema)
  out="$CACHE/$ns-$name-$version.json"
  if [[ ! -s "$out" ]]; then
    command -v terraform >/dev/null || { echo "terraform not installed" >&2; exit 1; }
    work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
    cat >"$work/main.tf" <<EOF
terraform {
  required_providers {
    $name = {
      source  = "$ns/$name"
      version = "= $version"
    }
  }
}
EOF
    echo "downloading $ns/$name $version (one-time, cached)..." >&2
    (cd "$work" && terraform init -backend=false -input=false -no-color >/dev/null &&
      terraform providers schema -json >"$out.tmp") && mv "$out.tmp" "$out"
  fi
  echo "schema: $out" >&2
  [[ $# -ge 4 ]] || exit 0
  python3 - "$out" "$4" <<'PY'
import json, sys
path, rtype = sys.argv[1], sys.argv[2]
schemas = json.load(open(path))["provider_schemas"]
for prov, s in schemas.items():
    for kind in ("resource_schemas", "data_source_schemas"):
        block = s.get(kind, {}).get(rtype)
        if block is None:
            continue
        print(f"{rtype} ({kind[:-8]}, {prov}, schema version {block.get('version')})")
        def walk(b, indent="  "):
            for name, a in sorted(b.get("attributes", {}).items()):
                flags = [f for f in ("required", "optional", "computed", "sensitive", "deprecated") if a.get(f)]
                print(f"{indent}{name}: {json.dumps(a.get('type', a.get('nested_type', '?')))} [{', '.join(flags)}]")
            for name, nb in sorted(b.get("block_types", {}).items()):
                lim = f"min {nb.get('min_items', 0)}, max {nb.get('max_items', 'inf')}"
                print(f"{indent}{name} {{ }}  block, nesting={nb.get('nesting_mode')}, {lim}")
                walk(nb.get("block", {}), indent + "  ")
        walk(block["block"])
        sys.exit(0)
print(f"{rtype}: not found in this provider version", file=sys.stderr)
sys.exit(1)
PY
  ;;
docs)
  [[ $# -ge 4 ]] || usage
  rtype="$4"
  case "$name" in aws | azurerm) ;; *) echo "docs mode supports aws and azurerm" >&2; exit 2 ;; esac
  [[ "$rtype" =~ ^${name}_[a-z0-9_]+$ ]] || { echo "resource type must start with ${name}_" >&2; exit 2; }
  page="${rtype#"${name}"_}"
  out="$CACHE/docs-$name-$version-$page.md"
  if [[ ! -s "$out" ]]; then
    url="https://raw.githubusercontent.com/hashicorp/terraform-provider-$name/v$version/website/docs/r/$page.html.markdown"
    curl -fsSL --max-time 30 --max-filesize 5000000 "$url" -o "$out.tmp" || { rm -f "$out.tmp"; echo "fetch failed: $url" >&2; exit 1; }
    mv "$out.tmp" "$out"
  fi
  echo "docs: $out" >&2
  if [[ $# -ge 5 ]]; then grep -n -- "\`$5\`" "$out" || { echo "attribute '$5' not mentioned" >&2; exit 1; }; fi
  ;;
*) usage ;;
esac
