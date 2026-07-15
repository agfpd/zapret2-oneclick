#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZAPRET_VERSION="v1.0.2"
ZAPRET_ARCHIVE_SHA256="45f90e1c70db104a735cd0f99e5644cea84689bf05dadb498953f334999b1ebb"
WIN_BUNDLE_COMMIT="0e9e3fbfb04a1681f3f8b5eb644dee4ecedcccf0"
ZAPRET_URL="https://github.com/bol-van/zapret2/releases/download/${ZAPRET_VERSION}/zapret2-${ZAPRET_VERSION}.zip"
ZAPRET_MANIFEST_URL="https://github.com/bol-van/zapret2/releases/download/${ZAPRET_VERSION}/sha256sum.txt"
WIN_BUNDLE_URL="https://github.com/bol-van/zapret-win-bundle.git"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Downloading zapret2 ${ZAPRET_VERSION}..."
curl --fail --location --retry 3 --output "$work/zapret2.zip" "$ZAPRET_URL"
actual="$(shasum -a 256 "$work/zapret2.zip" | awk '{print $1}')"
if [[ "$actual" != "$ZAPRET_ARCHIVE_SHA256" ]]; then
  echo "zapret2 archive SHA-256 mismatch: expected $ZAPRET_ARCHIVE_SHA256, got $actual" >&2
  exit 1
fi
unzip -q "$work/zapret2.zip" -d "$work/zapret2"
src="$work/zapret2/zapret2-${ZAPRET_VERSION}"
curl --fail --location --retry 3 --output "$work/sha256sum.txt" "$ZAPRET_MANIFEST_URL"
manifest_hash="$(shasum -a 256 "$work/sha256sum.txt" | awk '{print $1}')"
if [[ "$manifest_hash" != "4e2bcd47fa7d90adfe740679f82d6378c957b7f14f24657cdbe3285b8e840e69" ]]; then
  echo "official zapret2 manifest SHA-256 mismatch" >&2
  exit 1
fi
cp "$work/sha256sum.txt" "$ROOT/checksums/zapret2-v1.0.2-official.sha256"

echo "Fetching official Windows bundle ${WIN_BUNDLE_COMMIT}..."
git clone --quiet --no-checkout "$WIN_BUNDLE_URL" "$work/win-bundle"
git -C "$work/win-bundle" checkout --quiet "$WIN_BUNDLE_COMMIT"
if [[ "$(git -C "$work/win-bundle" rev-parse HEAD)" != "$WIN_BUNDLE_COMMIT" ]]; then
  echo "win bundle commit verification failed" >&2
  exit 1
fi

rm -rf "$ROOT/vendor/zapret2"
mkdir -p \
  "$ROOT/vendor/zapret2/nfq2" \
  "$ROOT/vendor/zapret2/service" \
  "$ROOT/vendor/zapret2/mdig" \
  "$ROOT/vendor/zapret2/ip2net" \
  "$ROOT/vendor/zapret2/windivert.filter"

cp "$src/binaries/windows-x86_64/winws2.exe" "$ROOT/vendor/zapret2/nfq2/"
cp "$src/binaries/windows-x86_64/WinDivert.dll" "$ROOT/vendor/zapret2/nfq2/"
cp "$src/binaries/windows-x86_64/WinDivert64.sys" "$ROOT/vendor/zapret2/nfq2/"
cp "$src/binaries/windows-x86_64/winws2.exe" "$ROOT/vendor/zapret2/service/"
cp "$src/binaries/windows-x86_64/WinDivert.dll" "$ROOT/vendor/zapret2/service/"
cp "$src/binaries/windows-x86_64/WinDivert64.sys" "$ROOT/vendor/zapret2/service/"
cp "$src/binaries/windows-x86_64/cygwin1.dll" "$ROOT/vendor/zapret2/service/"
cp "$src/binaries/windows-x86_64/killall.exe" "$ROOT/vendor/zapret2/service/"
cp "$src/binaries/windows-x86_64/mdig.exe" "$ROOT/vendor/zapret2/mdig/"
cp "$src/binaries/windows-x86_64/ip2net.exe" "$ROOT/vendor/zapret2/ip2net/"
cp -R "$src/lua" "$src/files" "$src/common" "$src/blockcheck2.d" "$src/docs" "$ROOT/vendor/zapret2/"
cp "$src/blockcheck2.sh" "$src/config.default" "$ROOT/vendor/zapret2/"
cp "$src/init.d/windivert.filter.examples/"*.txt "$ROOT/vendor/zapret2/windivert.filter/"
if [[ ! -d "$ROOT/vendor/cygwin" ]]; then
  cp -R "$work/win-bundle/cygwin" "$ROOT/vendor/cygwin"
  echo "WARNING: seeded the upstream Cygwin snapshot; run Build-CygwinRuntime.ps1 before release." >&2
fi

patch -d "$ROOT/vendor/zapret2" -p1 <"$ROOT/patches/blockcheck2-machine-report.patch"
patch -d "$ROOT/vendor/zapret2" -p1 <"$ROOT/patches/blockcheck2-custom-candidates.patch"
patch -d "$ROOT/vendor/zapret2" -p1 <"$ROOT/patches/blockcheck2-native-winws-launch.patch"
"$ROOT/build/verify-official-binaries.sh"
"$ROOT/build/update-manifest.sh"

echo "Vendor import complete. Run check-release-readiness.ps1 before packaging."
