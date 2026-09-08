#!/usr/bin/env python3
"""Summarize selected open Leica M11-P R2Y categories from a verified unpacked image.

This tool is intentionally narrow.  It does not emit firmware/resource bytes.
For the currently open R2A categories it records descriptor metadata, per-map
hashes, and decoded 16-bit words only for small maps (<=128 bytes).

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
            if len(raw) <= SMALL_MAP_LIMIT and len(raw) % 2 == 0:
                n = len(raw) // 2
                row["raw_i16_le"] = list(struct.unpack("<" + "h" * n, raw))
                row["raw_u16_le"] = list(struct.unpack("<" + "H" * n, raw))
            rows.append(row)
        selected[str(category)] = rows

    return {
        "schema": "m11camera.forensics.r2a_open_categories.v1",
        "unpacked_sha256": actual_sha,
        "r2ys_offset_abs": base,
        "r2ys_size": r2y_size,
        "database_header_rel": db_header_rel,
        "categories": selected,
        "policy": (
            "Derived descriptor metadata/hashes only; decoded words are emitted only "
            "for maps <=128 bytes. No firmware or R2YS resource bytes are written."
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
