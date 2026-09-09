#!/usr/bin/env python3
"""Workflow-facing CLI for :mod:`m11_romfs_probe`.

The core parser intentionally remains a small testable library.  This wrapper
restores the command-line interface expected by the official-firmware workflow:
scan ROMFS images, list files, find exact paths/basenames and carve only those
explicitly requested files into an ephemeral directory.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from m11_romfs_probe import (
    RECORDED_LANDMARKS,
    entry_bytes,
    find_entries,
    find_romfs,
    parse_romfs,
    walk_romfs,
)


def _safe_extract_path(root: Path, fs_index: int, entry_path: str) -> Path:
    relative = entry_path.lstrip("/")
    if not relative or ".." in Path(relative).parts:
        raise ValueError(f"unsafe ROMFS extraction path: {entry_path!r}")
    return root / f"romfs_{fs_index}" / relative


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware", type=Path, help="decompressed M11/M11-P firmware image")
    ap.add_argument("--scan", action="store_true", help="scan for all ROMFS magic offsets")
    ap.add_argument("--list-files", action="store_true", help="list parsed ROMFS entries")
    ap.add_argument("--find-file", action="append", default=[], help="exact absolute path or basename")
    ap.add_argument("--extract-found-dir", type=Path, help="ephemerally carve requested --find-file matches")
    args = ap.parse_args()

    if args.extract_found_dir is not None and not args.find_file:
        ap.error("--extract-found-dir requires at least one --find-file")

    data = args.firmware.read_bytes()
    print(f"input={args.firmware} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")

    recorded = dict(RECORDED_LANDMARKS)
    offsets = find_romfs(data) if args.scan else [offset for offset, _ in RECORDED_LANDMARKS]
    print(f"ROMFS offsets: {[hex(x) for x in offsets]}")

    total_matches = 0
    for fs_index, offset in enumerate(offsets, start=1):
        info = parse_romfs(data, offset, recorded.get(offset))
        romfs = data[offset : offset + info.declared_size]
        entries = walk_romfs(romfs, info.root_header_rel, allow_duplicate_headers=True)
        print(
            f"ROMFS {fs_index}: offset={offset:#x} declared={info.declared_size} "
            f"recorded={info.recorded_size} volume={info.volume_name!r} "
            f"root={info.root_header_rel:#x} sha256={info.sha256}"
        )

        if args.list_files or (not args.scan and not args.find_file and args.extract_found_dir is None):
            for entry in entries:
                print(
                    f"  {entry.path} type={entry.type_name} exec={int(entry.executable)} "
                    f"hdr={entry.header_rel:#x} next={entry.next_rel:#x} spec={entry.spec_info:#x} "
                    f"size={entry.size} data={entry.data_rel:#x} checksum={entry.checksum:#010x}"
                )

        for needle in args.find_file:
            matches = find_entries(entries, needle)
            for entry in matches:
                total_matches += 1
                absolute_data = offset + entry.data_rel
                print(
                    f"FOUND needle={needle!r} path={entry.path} type={entry.type_name} "
                    f"size={entry.size} romfs_data={entry.data_rel:#x} firmware_data={absolute_data:#x}"
                )
                if args.extract_found_dir is not None:
                    if entry.type_id != 2:
                        print(f"  SKIP extract: {entry.path} is {entry.type_name}, not regular file")
                        continue
                    out = _safe_extract_path(args.extract_found_dir, fs_index, entry.path)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    payload = entry_bytes(romfs, entry)
                    out.write_bytes(payload)
                    print(
                        f"  EXTRACT {out} bytes={len(payload)} "
                        f"sha256={hashlib.sha256(payload).hexdigest()}"
                    )

    if args.find_file:
        print(f"requested_match_count={total_matches}")


if __name__ == "__main__":
    main()
