#!/usr/bin/env python3
"""Trace Leica M11-P gamma-related firmware strings to their containing consumers.

This is an evidence-gathering tool, not a renderer implementation. It accepts an
already decompressed M11/M11-P firmware image and reports only derived metadata:
string offsets, ROMFS ownership, file hashes/ELF architecture, and nearby ASCII
labels. It deliberately does not emit or persist proprietary firmware bytes.

R2A goal: narrow the consumer trace for Category 15/20 gamma data, especially
`RGBYB TABLE`, Yb access, table-index selectors, and surrounding gamma labels.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from m11_romfs_probe import (
    RECORDED_LANDMARKS,
    entry_bytes,
    parse_romfs,
    walk_romfs,
)

EXPECTED_UNPACKED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"

# Keep this list explicit so later evidence reviews know exactly what was sought.
NEEDLES = [
    b"RGBYB TABLE",
    b"RGBYB",
    b"Yb gamma",
    b"YB gamma",
    b"Yb",
    b"gamma",
    b"Gamma",
    b"GAMMA",
]

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


@dataclass(frozen=True)
class FileOwner:
    romfs_index: int
    romfs_base: int
    path: str
    file_abs: int
    file_size: int
    payload: bytes

    @property
    def file_end(self) -> int:
        return self.file_abs + self.file_size

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def all_hits(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return hits
        hits.append(pos)
        start = pos + 1


def build_file_owners(data: bytes) -> tuple[list[FileOwner], list[str]]:
    owners: list[FileOwner] = []
    notes: list[str] = []
    for romfs_index, (romfs_base, recorded_size) in enumerate(RECORDED_LANDMARKS, start=1):
        info = parse_romfs(data, romfs_base, recorded_size)
        romfs = data[romfs_base : romfs_base + info.declared_size]
        entries = walk_romfs(romfs, info.root_header_rel)
        notes.append(
            f"ROMFS {romfs_index}: base=0x{romfs_base:08x}, "
            f"declared={info.declared_size}, entries={len(entries)}, volume={info.volume_name!r}"
        )
        for entry in entries:
            if entry.type_id != 2:
                continue
            payload = entry_bytes(romfs, entry)
            owners.append(
                FileOwner(
                    romfs_index=romfs_index,
                    romfs_base=romfs_base,
                    path=entry.path,
                    file_abs=romfs_base + entry.data_rel,
                    file_size=entry.size,
                    payload=payload,
                )
            )
    owners.sort(key=lambda item: item.file_abs)
    return owners, notes


def owner_for_offset(owners: list[FileOwner], absolute_offset: int) -> FileOwner | None:
    for owner in owners:
        if owner.file_abs <= absolute_offset < owner.file_end:
            return owner
    return None


def elf_summary(payload: bytes) -> str:
    if len(payload) < 20 or payload[:4] != b"\x7fELF":
        return "not ELF"
    elf_class = payload[4]
    elf_data = payload[5]
    endian = "<" if elf_data == 1 else ">" if elf_data == 2 else None
    if endian is None:
        return f"ELF class={elf_class} data={elf_data} machine=unknown"
    machine = struct.unpack_from(endian + "H", payload, 18)[0]
    machine_name = {
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        40: "ARM",
        62: "x86-64",
        183: "AArch64",
    }.get(machine, f"machine-{machine}")
    class_name = {1: "ELF32", 2: "ELF64"}.get(elf_class, f"class-{elf_class}")
    data_name = {1: "LE", 2: "BE"}.get(elf_data, f"data-{elf_data}")
    return f"{class_name} {data_name} {machine_name}"


def nearby_ascii(payload: bytes, center: int, radius: int = 0x500) -> list[tuple[int, str]]:
    start = max(0, center - radius)
    end = min(len(payload), center + radius)
    window = payload[start:end]
    candidates: list[tuple[int, str]] = []
    for match in PRINTABLE_RE.finditer(window):
        file_off = start + match.start()
        text = match.group().decode("ascii", errors="replace")
        candidates.append((file_off, text))
    candidates.sort(key=lambda item: (abs(item[0] - center), item[0]))
    return candidates[:32]


def interesting_strings(payload: bytes) -> list[tuple[int, str]]:
    terms = ("gamma", "rgbyb", "yb", "table", "index", "r2y", "tone", "yc", "chroma")
    out: list[tuple[int, str]] = []
    for match in PRINTABLE_RE.finditer(payload):
        text = match.group().decode("ascii", errors="replace")
        lower = text.lower()
        if any(term in lower for term in terms):
            out.append((match.start(), text))
    return out


def emit_report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    owners, romfs_notes = build_file_owners(data)
    lines: list[str] = []
    lines.append("# M11-P R2A gamma consumer string trace")
    lines.append("")
    lines.append("Evidence state: **derived directly from official M11-P 2.6.1 unpacked firmware**.")
    lines.append("")
    lines.append(f"- unpacked size: `{len(data)}`")
    lines.append(f"- unpacked SHA-256: `{digest}`")
    for note in romfs_notes:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("## Global target hits")
    lines.append("")

    hit_rows: list[tuple[bytes, int, FileOwner | None]] = []
    for needle in NEEDLES:
        hits = all_hits(data, needle)
        lines.append(f"### `{needle.decode('ascii', errors='replace')}` — {len(hits)} hit(s)")
        if not hits:
            lines.append("")
            lines.append("No hits.")
            lines.append("")
            continue
        lines.append("")
        lines.append("| absolute offset | region / owner | file offset |")
        lines.append("|---:|---|---:|")
        for absolute in hits[:200]:
            owner = owner_for_offset(owners, absolute)
            hit_rows.append((needle, absolute, owner))
            if owner is None:
                lines.append(f"| `0x{absolute:08x}` | outside verified ROMFS files | — |")
            else:
                file_off = absolute - owner.file_abs
                lines.append(
                    f"| `0x{absolute:08x}` | ROMFS {owner.romfs_index} `{owner.path}` | `0x{file_off:x}` |"
                )
        if len(hits) > 200:
            lines.append(f"\nFirst 200 shown; {len(hits) - 200} additional hit(s) omitted.")
        lines.append("")

    # Deduplicate files that own any target hit.
    owned: dict[tuple[int, str, int], FileOwner] = {}
    for _, _, owner in hit_rows:
        if owner is not None:
            owned[(owner.romfs_index, owner.path, owner.file_abs)] = owner

    lines.append("## Consumer-file candidates")
    lines.append("")
    if not owned:
        lines.append("No target hit belongs to a structured ROMFS regular file.")
        lines.append("")
    else:
        for _, owner in sorted(owned.items(), key=lambda item: item[1].file_abs):
            lines.append(f"### ROMFS {owner.romfs_index} `{owner.path}`")
            lines.append("")
            lines.append(f"- absolute file start: `0x{owner.file_abs:08x}`")
            lines.append(f"- size: `{owner.file_size}`")
            lines.append(f"- SHA-256: `{owner.sha256}`")
            lines.append(f"- format: `{elf_summary(owner.payload)}`")
            lines.append("")

            file_hits = []
            for needle in NEEDLES:
                for file_off in all_hits(owner.payload, needle):
                    file_hits.append((file_off, needle.decode("ascii", errors="replace")))
            file_hits.sort()
            lines.append("Target occurrences in this file:")
            lines.append("")
            for file_off, label in file_hits:
                lines.append(f"- `0x{file_off:x}` — `{label}`")
            lines.append("")

            labels = interesting_strings(owner.payload)
            lines.append("Related labels in the same file (offset order):")
            lines.append("")
            for file_off, text in labels[:240]:
                safe = text.replace("`", "'")
                lines.append(f"- `0x{file_off:x}` — `{safe}`")
            if len(labels) > 240:
                lines.append(f"- … {len(labels) - 240} additional related label(s) omitted")
            lines.append("")

            # Emit local ASCII neighbourhoods for the most discriminating labels only.
            discriminating = []
            for label in (b"RGBYB TABLE", b"RGBYB", b"Yb gamma", b"YB gamma"):
                for file_off in all_hits(owner.payload, label):
                    discriminating.append((file_off, label.decode("ascii", errors="replace")))
            for file_off, label in sorted(set(discriminating)):
                lines.append(f"#### Nearby ASCII around `{label}` at file `0x{file_off:x}`")
                lines.append("")
                for nearby_off, text in nearby_ascii(owner.payload, file_off):
                    safe = text.replace("`", "'")
                    delta = nearby_off - file_off
                    lines.append(f"- `{delta:+#x}` / file `0x{nearby_off:x}` — `{safe}`")
                lines.append("")

    lines.append("## Non-ROMFS target clusters")
    lines.append("")
    non_romfs = [(needle, absolute) for needle, absolute, owner in hit_rows if owner is None]
    if not non_romfs:
        lines.append("All recorded target hits map to structured ROMFS regular files.")
    else:
        for needle, absolute in non_romfs[:100]:
            start = max(0, absolute - 0x300)
            end = min(len(data), absolute + 0x300)
            labels = []
            for match in PRINTABLE_RE.finditer(data[start:end]):
                label_abs = start + match.start()
                text = match.group().decode("ascii", errors="replace").replace("`", "'")
                labels.append((abs(label_abs - absolute), label_abs, text))
            labels.sort()
            lines.append(f"### `{needle.decode('ascii', errors='replace')}` at `0x{absolute:08x}`")
            lines.append("")
            for _, label_abs, text in labels[:24]:
                delta = label_abs - absolute
                lines.append(f"- `{delta:+#x}` / abs `0x{label_abs:08x}` — `{text}`")
            lines.append("")
        if len(non_romfs) > 100:
            lines.append(f"Additional non-ROMFS hits omitted: {len(non_romfs) - 100}")

    lines.append("")
    lines.append("## Interpretation boundary")
    lines.append("")
    lines.append(
        "This report establishes string ownership and candidate consumer binaries only. "
        "It does **not** yet prove pixel execution order, gamma channel/domain, or Category 15/20 "
        "hardware arithmetic. Those remain OPEN until code/register xrefs are traced."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path, help="decompressed official M11/M11-P firmware image")
    ap.add_argument("--output", type=Path, required=True, help="derived Markdown report path")
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    report = emit_report(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report + "\n")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
