#!/usr/bin/env python3
"""Probe/carve ROMFS images from a decompressed Leica M11-P firmware image.

This tool encodes only recorded filesystem landmarks plus the public ROMFS
superblock format. It does not encode unverified CC/tone/gamma record offsets.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

ROMFS_MAGIC = b"-rom1fs-"
RECORDED_LANDMARKS = (
    (0x00E3A160, 3_629_024),
    (0x0333DF70, 43_912_464),
)


@dataclass(frozen=True)
class RomfsImage:
    offset: int
    declared_size: int
    recorded_size: int | None
    volume_name: str
    sha256: str


def align16(value: int) -> int:
    return (value + 15) & ~15


def read_c_string(data: bytes, start: int, limit: int) -> str:
    end_limit = min(len(data), start + limit)
    end = data.find(b"\x00", start, end_limit)
    if end < 0:
        end = end_limit
    return data[start:end].decode("ascii", errors="replace")


def parse_romfs(data: bytes, offset: int, recorded_size: int | None = None) -> RomfsImage:
    if offset < 0 or offset + 16 > len(data):
        raise ValueError(f"ROMFS offset {offset:#x} lies outside image")
    if data[offset : offset + 8] != ROMFS_MAGIC:
        got = data[offset : offset + 8]
        raise ValueError(
            f"ROMFS magic missing at {offset:#x}: got {got!r}, expected {ROMFS_MAGIC!r}"
        )

    declared_size = struct.unpack_from(">I", data, offset + 8)[0]
    if declared_size < 16:
        raise ValueError(f"invalid ROMFS declared size {declared_size} at {offset:#x}")
    if offset + declared_size > len(data):
        raise ValueError(
            f"ROMFS at {offset:#x} extends beyond image: "
            f"{declared_size} bytes from {len(data)}-byte input"
        )

    volume_name = read_c_string(data, offset + 16, 4096)
    payload = data[offset : offset + declared_size]
    return RomfsImage(
        offset=offset,
        declared_size=declared_size,
        recorded_size=recorded_size,
        volume_name=volume_name,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def find_romfs(data: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        pos = data.find(ROMFS_MAGIC, start)
        if pos < 0:
            break
        found.append(pos)
        start = pos + 1
    return found


def search_ascii(data: bytes, needle: str) -> list[int]:
    raw = needle.encode("ascii")
    out: list[int] = []
    start = 0
    while True:
        pos = data.find(raw, start)
        if pos < 0:
            break
        out.append(pos)
        start = pos + 1
    return out


def print_image(info: RomfsImage) -> None:
    recorded = "n/a" if info.recorded_size is None else str(info.recorded_size)
    delta = (
        "n/a"
        if info.recorded_size is None
        else str(info.declared_size - info.recorded_size)
    )
    print(f"ROMFS offset       : {info.offset:#010x}")
    print(f"declared size      : {info.declared_size}")
    print(f"recorded size      : {recorded}")
    print(f"declared-recorded  : {delta}")
    print(f"volume name        : {info.volume_name!r}")
    print(f"sha256             : {info.sha256}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path, help="decompressed M11/M11-P firmware image")
    ap.add_argument(
        "--scan",
        action="store_true",
        help="scan the whole image for ROMFS magic in addition to recorded landmarks",
    )
    ap.add_argument(
        "--search",
        action="append",
        default=[],
        help="ASCII string to locate, e.g. --search r2y.bin (repeatable)",
    )
    ap.add_argument(
        "--carve-dir",
        type=Path,
        help="write verified ROMFS images to this directory",
    )
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    print(f"input: {args.unpacked}")
    print(f"size : {len(data)} bytes")
    print(f"sha256: {hashlib.sha256(data).hexdigest()}")

    infos: list[RomfsImage] = []
    print("\nRecorded landmark verification")
    for offset, recorded_size in RECORDED_LANDMARKS:
        try:
            info = parse_romfs(data, offset, recorded_size)
        except ValueError as exc:
            print(f"FAIL {offset:#010x}: {exc}")
            continue
        infos.append(info)
        print("\nPASS")
        print_image(info)

    if args.scan:
        print("\nROMFS magic scan")
        offsets = find_romfs(data)
        print(f"found {len(offsets)} candidate(s):")
        for offset in offsets:
            print(f"  {offset:#010x}")

    for needle in args.search:
        hits = search_ascii(data, needle)
        print(f"\nASCII search {needle!r}: {len(hits)} hit(s)")
        for pos in hits[:100]:
            print(f"  {pos:#010x}")
        if len(hits) > 100:
            print(f"  ... {len(hits) - 100} more")

    if args.carve_dir:
        args.carve_dir.mkdir(parents=True, exist_ok=True)
        for index, info in enumerate(infos, start=1):
            out = args.carve_dir / f"m11p_romfs_{index}_{info.offset:08x}.bin"
            out.write_bytes(data[info.offset : info.offset + info.declared_size])
            print(f"carved {out}")

    if len(infos) != len(RECORDED_LANDMARKS):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
