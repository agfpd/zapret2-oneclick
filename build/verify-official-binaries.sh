#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
official="$ROOT/checksums/zapret2-v1.0.2-official.sha256"
prefix="zapret2-v1.0.2/binaries/windows-x86_64"

files=(
  "$ROOT/vendor/zapret2/nfq2/winws2.exe"
  "$ROOT/vendor/zapret2/nfq2/WinDivert.dll"
  "$ROOT/vendor/zapret2/nfq2/WinDivert64.sys"
  "$ROOT/vendor/zapret2/service/winws2.exe"
  "$ROOT/vendor/zapret2/service/WinDivert.dll"
  "$ROOT/vendor/zapret2/service/WinDivert64.sys"
  "$ROOT/vendor/zapret2/service/cygwin1.dll"
  "$ROOT/vendor/zapret2/service/killall.exe"
  "$ROOT/vendor/zapret2/mdig/mdig.exe"
  "$ROOT/vendor/zapret2/ip2net/ip2net.exe"
)

for file in "${files[@]}"; do
  name="${file##*/}"
  expected="$(awk -v path="$prefix/$name" '$2 == path { print $1 }' "$official")"
  actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  if [[ -z "$expected" || "$actual" != "$expected" ]]; then
    echo "official binary verification failed: $file" >&2
    exit 1
  fi
done
echo "Official zapret2 x86_64 binaries verified."
