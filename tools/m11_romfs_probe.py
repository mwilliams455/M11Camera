#!/usr/bin/env python3
"""Probe, walk and carve ROMFS images from decompressed Leica M11-P firmware.

This tool encodes only recorded M11-P filesystem landmarks plus the documented
Linux ROMFS on-disk format. It deliberately does not encode unverified
CC/tone/gamma record offsets.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROMFS_MAGIC = b"-rom1fs-"
RECORDED_LANDMARKS = (
    (0x00E3A160, 3_629_024),
    (0x0333DF70, 43_912_464),
)

ROMFS_TYPES = {
    0: "hardlink",
    1: "directory",
    2: "file",
    3: "symlink",
    4: "block",
    5: "char",
    6: "socket",
    7: "fifo",
}


@dataclass(frozen=True)
class RomfsImage:
    offset: int
    declared_size: int
    recorded_size: int | None
    volume_name: str
    root_header_rel: int
    sha256: str


@dataclass(frozen=True)
class RomfsEntry:
    path: str
    header_rel: int
    next_rel: int
    type_id: int
    executable: bool
    spec_info: int
    size: int
    checksum: int
    name: str
    data_rel: int

    @property
    def type_name(self) -> str:
        return ROMFS_TYPES.get(self.type_id, f"unknown-{self.type_id}")


def align16(value: int) -> int:
    return (value + 15) & ~15


def _find_nul(data: bytes, start: int, end: int, label: str) -> int:
    pos = data.find(b"\x00", start, min(end, len(data)))
    if pos < 0:
        raise ValueError(f"unterminated {label} starting at {start:#x}")
    return pos


def read_c_string(data: bytes, start: int, limit: int) -> str:
    end = _find_nul(data, start, start + limit, "string")
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
    if declared_size < 32:
        raise ValueError(f"invalid ROMFS declared size {declared_size} at {offset:#x}")
    if offset + declared_size > len(data):
        raise ValueError(
            f"ROMFS at {offset:#x} extends beyond image: "
            f"{declared_size} bytes from {len(data)}-byte input"
        )

    fs_end = offset + declared_size
    volume_end = _find_nul(data, offset + 16, min(fs_end, offset + 4096), "volume name")
    volume_name = data[offset + 16 : volume_end].decode("ascii", errors="replace")
    root_header_rel = align16(volume_end + 1 - offset)
    if root_header_rel + 16 > declared_size:
        raise ValueError("ROMFS volume label leaves no room for root file header")

    payload = data[offset:fs_end]
    return RomfsImage(
        offset=offset,
        declared_size=declared_size,
        recorded_size=recorded_size,
        volume_name=volume_name,
        root_header_rel=root_header_rel,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def parse_entry(romfs: bytes, header_rel: int, path: str) -> RomfsEntry:
    if header_rel == 0:
        raise ValueError("zero is a null ROMFS file-header pointer")
    if header_rel & 0xF:
        raise ValueError(f"unaligned ROMFS file header {header_rel:#x}")
    if header_rel < 0 or header_rel + 16 > len(romfs):
        raise ValueError(f"ROMFS file header {header_rel:#x} lies outside filesystem")

    next_raw, spec_info, size, checksum = struct.unpack_from(">IIII", romfs, header_rel)
    type_id = next_raw & 0x7
    executable = bool(next_raw & 0x8)
    next_rel = next_raw & 0xFFFFFFF0

    if next_rel and (next_rel & 0xF or next_rel + 16 > len(romfs)):
        raise ValueError(
            f"invalid next ROMFS file-header pointer {next_rel:#x} from {header_rel:#x}"
        )

    name_start = header_rel + 16
    name_end = _find_nul(
        romfs,
        name_start,
        min(len(romfs), name_start + 4096),
        "ROMFS file name",
    )
    name = romfs[name_start:name_end].decode("utf-8", errors="replace")
    data_rel = align16(name_end + 1)

    if type_id in (2, 3) and data_rel + size > len(romfs):
        raise ValueError(
            f"ROMFS {ROMFS_TYPES[type_id]} {path!r} data extends beyond filesystem: "
            f"{data_rel:#x}+{size:#x}>{len(romfs):#x}"
        )

    return RomfsEntry(
        path=path,
        header_rel=header_rel,
        next_rel=next_rel,
        type_id=type_id,
        executable=executable,
        spec_info=spec_info,
        size=size,
        checksum=checksum,
        name=name,
        data_rel=data_rel,
    )


def _join_path(parent: str, name: str) -> str:
    if parent == "/":
        return f"/{name}"
    return f"{parent.rstrip('/')}/{name}"


def walk_romfs(
    romfs: bytes,
    root_header_rel: int,
    *,
    allow_duplicate_headers: bool = False,
) -> list[RomfsEntry]:
    """Return the ROMFS tree in deterministic directory/sibling order.

    Directory `spec_info` is the relative offset of its first child. Hard links
    are listed but never recursively followed, avoiding conventional hard-link
    cycles.  By default, a header referenced from more than one directory chain
    remains an error because it can indicate a corrupt parse.

    For forensic best-effort ownership scans, ``allow_duplicate_headers=True``
    permits an already-seen header to be skipped while following its encoded
    sibling pointer.  The duplicate is never emitted twice or recursively
    followed, so this mode cannot manufacture additional file payloads.
    """
    root = parse_entry(romfs, root_header_rel, "/")
    entries: list[RomfsEntry] = [root]
    seen_headers: set[int] = {root_header_rel}
    active_dirs: set[int] = set()

    def walk_chain(first_rel: int, parent_path: str) -> None:
        rel = first_rel
        sibling_seen: set[int] = set()
        while rel:
            if rel in sibling_seen:
                raise ValueError(f"ROMFS sibling loop at {rel:#x}")
            sibling_seen.add(rel)
            if rel in seen_headers:
                if not allow_duplicate_headers:
                    raise ValueError(f"ROMFS file header {rel:#x} referenced more than once")
                duplicate = parse_entry(romfs, rel, parent_path)
                rel = duplicate.next_rel
                continue

            # Parse once with a placeholder so the actual name can define path.
            probe = parse_entry(romfs, rel, parent_path)
            path = _join_path(parent_path, probe.name)
            entry = parse_entry(romfs, rel, path)
            entries.append(entry)
            seen_headers.add(rel)

            if entry.type_id == 1 and entry.spec_info and entry.name not in (".", ".."):
                if rel in active_dirs:
                    raise ValueError(f"ROMFS directory recursion loop at {rel:#x}")
                active_dirs.add(rel)
                walk_chain(entry.spec_info, path)
                active_dirs.remove(rel)

            rel = entry.next_rel

    if root.type_id != 1:
        raise ValueError(
            f"ROMFS root header at {root_header_rel:#x} is {root.type_name}, not directory"
        )
    if root.spec_info:
        active_dirs.add(root_header_rel)
        walk_chain(root.spec_info, "/")
        active_dirs.remove(root_header_rel)
    return entries


def entry_bytes(romfs: bytes, entry: RomfsEntry) -> bytes:
    if entry.type_id not in (2, 3):
        raise ValueError(f"{entry.path} is {entry.type_name}, not file/symlink data")
    return romfs[entry.data_rel : entry.data_rel + entry.size]


def find_entries(entries: list[RomfsEntry], needle: str) -> list[RomfsEntry]:
    """Match an exact absolute path or an exact basename."""
    wanted = PurePosixPath(needle)
    if str(wanted).startswith("/"):
        return [e for e in entries if e.path == str(wanted)]
    return [e for e in entries if PurePosixPath(e.path).name == needle]


def find_romfs(data: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        pos = data.find(ROMFS_MAGIC, start)
        if pos < 0:
            return found
        found.append(pos)
        start = pos + 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware", type=Path, help="decompressed M11/M11-P firmware image")
    args = ap.parse_args()

    data = args.firmware.read_bytes()
    print(f"input={args.firmware} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
    print(f"all ROMFS magic offsets: {[hex(x) for x in find_romfs(data)]}")
    print()

    for index, (offset, recorded_size) in enumerate(RECORDED_LANDMARKS, start=1):
        info = parse_romfs(data, offset, recorded_size)
        romfs = data[offset : offset + info.declared_size]
        print(
            f"ROMFS {index}: offset={offset:#x} declared={info.declared_size} "
            f"recorded={recorded_size} volume={info.volume_name!r} "
            f"root={info.root_header_rel:#x} sha256={info.sha256}"
        )
        entries = walk_romfs(romfs, info.root_header_rel)
        for entry in entries:
            print(
                f"  {entry.path} type={entry.type_name} exec={int(entry.executable)} "
                f"hdr={entry.header_rel:#x} next={entry.next_rel:#x} spec={entry.spec_info:#x} "
                f"size={entry.size} data={entry.data_rel:#x} checksum={entry.checksum:#010x}"
            )


if __name__ == "__main__":
    main()
