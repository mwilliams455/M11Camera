#!/usr/bin/env python3
"""Summarize selected open Leica M11-P R2Y categories from a verified unpacked image.

This tool is intentionally narrow.  It does not emit firmware/resource bytes.
For the currently open R2A categories it records descriptor metadata, per-map
hashes, and decoded 16-bit words only for small maps (<=128 bytes).

It also enumerates every inferred six-byte R2YS map because the pinned public
Milbeaut ImR2yCtrlGamma control is exactly three uint16 fields
(GMEN/GMMD/GAMSW).  The six-byte scan is structural evidence only; it does not
assign semantics without a consumer match.

The canonical decompression/R2Y parser remains tools/extract_m11p_forensics.py.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, map_bytes, parse_r2y, sha

DEFAULT_CATEGORIES = (14, 16, 17, 25, 41)
SMALL_MAP_LIMIT = 128
GAMMA_CONTROL_BYTES = 6


def decoded_words(raw: bytes) -> dict:
    if len(raw) > SMALL_MAP_LIMIT or len(raw) % 2:
        return {}
    n = len(raw) // 2
    return {
        "raw_i16_le": list(struct.unpack("<" + "h" * n, raw)),
        "raw_u16_le": list(struct.unpack("<" + "H" * n, raw)),
    }


def summarize(data: bytes, categories: tuple[int, ...]) -> dict:
    actual_sha = sha(data)
    if actual_sha != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {actual_sha}")

    base, r2y_size, db_header_rel, descriptors = parse_r2y(data)
    by_category: dict[int, list[dict]] = {}
    for descriptor in descriptors:
        by_category.setdefault(descriptor["category"], []).append(descriptor)

    selected: dict[str, list[dict]] = {}
    for category in categories:
        rows = []
        for descriptor in by_category.get(category, []):
            raw = map_bytes(data, base, descriptor)
            row = {
                "descriptor": descriptor,
                "map_sha256": sha(raw),
                "map_size": len(raw),
            }
            row.update(decoded_words(raw))
            rows.append(row)
        selected[str(category)] = rows

    six_byte_controls = []
    for descriptor in descriptors:
        raw = map_bytes(data, base, descriptor)
        if len(raw) != GAMMA_CONTROL_BYTES:
            continue
        words = list(struct.unpack("<3H", raw))
        six_byte_controls.append(
            {
                "category": descriptor["category"],
                "index": descriptor["index"],
                "flags_hex": descriptor["flags_hex"],
                "descriptor_size": descriptor["descriptor_size"],
                "map_offset_abs": descriptor["map_offset_abs"],
                "map_sha256": sha(raw),
                "dependencies_s32": descriptor["dependencies_s32"],
                "raw_u16_le": words,
                "raw_i16_le": list(struct.unpack("<3h", raw)),
                "all_u16_binary": all(word in (0, 1) for word in words),
            }
        )

    return {
        "schema": "m11camera.forensics.r2a_open_categories.v2",
        "unpacked_sha256": actual_sha,
        "r2ys_offset_abs": base,
        "r2ys_size": r2y_size,
        "database_header_rel": db_header_rel,
        "categories": selected,
        "six_byte_controls": six_byte_controls,
        "policy": (
            "Derived descriptor metadata/hashes only; decoded words are emitted only "
            "for maps <=128 bytes. No firmware or R2YS resource bytes are written. "
            "Six-byte controls are enumerated structurally and are not semantically "
            "identified without consumer evidence."
        ),
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# M11-P R2A open-category summary",
        "",
        f"Unpacked SHA-256: `{report['unpacked_sha256']}`",
        "",
        "| Category | Descriptor count | Map sizes |",
        "| ---: | ---: | --- |",
    ]
    for category, rows in report["categories"].items():
        sizes = ", ".join(str(row["map_size"]) for row in rows) if rows else "none"
        lines.append(f"| {category} | {len(rows)} | {sizes} |")

    for category, rows in report["categories"].items():
        lines += ["", f"## Category {category}", ""]
        if not rows:
            lines.append("No descriptors.")
            continue
        for i, row in enumerate(rows):
            d = row["descriptor"]
            lines += [
                f"### Descriptor {i}",
                "",
                f"- index: `{d['index']}`",
                f"- flags: `{d['flags_hex']}`",
                f"- descriptor size: `{d['descriptor_size']}`",
                f"- map size: `{row['map_size']}`",
                f"- map offset: `0x{d['map_offset_abs']:08X}`",
                f"- map SHA-256: `{row['map_sha256']}`",
                f"- dependencies signed: `{d['dependencies_s32']}`",
            ]
            if "raw_i16_le" in row:
                lines.append(f"- raw int16 LE: `{row['raw_i16_le']}`")

    controls = report["six_byte_controls"]
    lines += [
        "",
        "## Six-byte R2YS control candidates",
        "",
        "Pinned public `ImR2yCtrlGamma` is 6 bytes (three uint16 fields). This table is structural only.",
        "",
        "| Category | Index | Flags | Offset | uint16 words | Binary triplet | SHA-256 |",
        "| ---: | ---: | --- | --- | --- | --- | --- |",
    ]
    if controls:
        for row in controls:
            lines.append(
                f"| {row['category']} | {row['index']} | `{row['flags_hex']}` | "
                f"`0x{row['map_offset_abs']:08X}` | `{row['raw_u16_le']}` | "
                f"{'yes' if row['all_u16_binary'] else 'no'} | `{row['map_sha256']}` |"
            )
    else:
        lines.append("| - | - | - | - | none | - | - |")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path, help="verified M11-P 2.6.1 unpacked firmware image")
    ap.add_argument("--json", type=Path, required=True, dest="json_path")
    ap.add_argument("--markdown", type=Path)
    ap.add_argument(
        "--categories",
        default=",".join(str(x) for x in DEFAULT_CATEGORIES),
        help="comma-separated R2Y category ids",
    )
    args = ap.parse_args()

    categories = tuple(int(x.strip(), 0) for x in args.categories.split(",") if x.strip())
    report = summarize(args.unpacked.read_bytes(), categories)
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.write_text(json.dumps(report, indent=2) + "\n")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(report))


if __name__ == "__main__":
    main()
