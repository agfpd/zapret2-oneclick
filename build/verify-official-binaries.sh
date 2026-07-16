#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
official="$ROOT/checksums/zapret2-v1.0.2-official.sha256"
prefix="zapret2-v1.0.2/binaries/windows-x86_64"

direct_files=(
  "$ROOT/vendor/zapret2/nfq2/WinDivert.dll"
  "$ROOT/vendor/zapret2/nfq2/WinDivert64.sys"
  "$ROOT/vendor/zapret2/service/WinDivert.dll"
  "$ROOT/vendor/zapret2/service/WinDivert64.sys"
  "$ROOT/vendor/zapret2/service/cygwin1.dll"
  "$ROOT/vendor/zapret2/service/killall.exe"
  "$ROOT/vendor/zapret2/ip2net/ip2net.exe"
)

for file in "${direct_files[@]}"; do
  name="${file##*/}"
  expected="$(awk -v path="$prefix/$name" '$2 == path { print $1 }' "$official")"
  actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  if [[ -z "$expected" || "$actual" != "$expected" ]]; then
    echo "official binary verification failed: $file" >&2
    exit 1
  fi
done

# winws2/mdig are deterministic derivatives of the official release: only
# DYNAMIC_BASE and HIGH_ENTROPY_VA are cleared for Cygwin fixed-address safety.
# Re-enable those two bits in a private copy, then demand exact official hash.
derived_files=(
  "$ROOT/vendor/zapret2/nfq2/winws2.exe"
  "$ROOT/vendor/zapret2/service/winws2.exe"
  "$ROOT/vendor/zapret2/mdig/mdig.exe"
)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for file in "${derived_files[@]}"; do
  name="${file##*/}"
  reconstructed="$tmp/${name}-${RANDOM}.exe"
  cp "$file" "$reconstructed"
  python3 "$ROOT/build/set-cygwin-pe-flags.py" --enable-aslr "$reconstructed" >/dev/null
  expected="$(awk -v path="$prefix/$name" '$2 == path { print $1 }' "$official")"
  actual="$(shasum -a 256 "$reconstructed" | awk '{print $1}')"
  if [[ -z "$expected" || "$actual" != "$expected" ]]; then
    echo "derived binary provenance verification failed: $file" >&2
    exit 1
  fi
done
echo "Official zapret2 x86_64 binaries and deterministic PE derivatives verified."
