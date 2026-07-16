#!/usr/bin/env python3
"""Deterministically toggle ASLR bits in x86_64 Cygwin PE images.

zapret2 v1.0.2 ships winws2/mdig with DYNAMIC_BASE and HIGH_ENTROPY_VA,
while Cygwin reserves process-global state at fixed addresses.  The release
derives its shipped images from the verified official bytes by clearing only
those two DllCharacteristics bits.  --enable-aslr is the inverse operation
used by verify-official-binaries.sh to prove official-byte provenance.
"""

from __future__ import annotations

import argparse
import pathlib
import struct


IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x20B
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
ASLR_MASK = (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
)


def characteristics_offset(data: bytes, path: pathlib.Path) -> int:
    if data[:2] != b"MZ":
        raise ValueError(f"{path}: missing MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path}: missing PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"{path}: expected AMD64 PE, got 0x{machine:04x}")
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != PE32_PLUS_MAGIC:
        raise ValueError(f"{path}: expected PE32+, got 0x{magic:04x}")
    return optional + 70


def update(path: pathlib.Path, enable: bool) -> tuple[int, int]:
    data = bytearray(path.read_bytes())
    offset = characteristics_offset(data, path)
    before = struct.unpack_from("<H", data, offset)[0]
    after = (before | ASLR_MASK) if enable else (before & ~ASLR_MASK)
    if enable and (before & ASLR_MASK) not in (0, ASLR_MASK):
        raise ValueError(f"{path}: partial ASLR state 0x{before:04x}")
    if not enable and (before & ASLR_MASK) != ASLR_MASK:
        raise ValueError(f"{path}: ASLR bits are not both set (0x{before:04x})")
    struct.pack_into("<H", data, offset, after)
    path.write_bytes(data)
    return before, after


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--disable-aslr", action="store_true")
    mode.add_argument("--enable-aslr", action="store_true")
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    for path in args.files:
        before, after = update(path, enable=args.enable_aslr)
        print(f"{path}: DllCharacteristics 0x{before:04x} -> 0x{after:04x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
