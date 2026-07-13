#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$ROOT/checksums/vendor.sha256"
tmp="${manifest}.tmp"

cd "$ROOT"
find vendor -type f -print0 |
  LC_ALL=C sort -z |
  while IFS= read -r -d '' file; do
    hash="$(shasum -a 256 "$file" | awk '{print $1}')"
    printf '%s *%s\n' "$hash" "$file"
  done >"$tmp"
mv "$tmp" "$manifest"
echo "Wrote $manifest"

