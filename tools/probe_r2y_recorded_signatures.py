#!/usr/bin/env python3
"""Locate recorded M11-P R2Y signatures without assuming descriptor layout.

The purpose is to turn historical constants into byte-level anchors in a newly
extracted r2y.bin. Exact record/category framing is deliberately *not* inferred
here; this tool only reports literal matches and small surrounding contexts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

CC0 = [495, -58, 63, 10, 601, -111, 49, -255, 705]
CC1 = [1041, -372, -157, -117, 630, -1, -4, -78, 595]
YCC = [77, 150, 29, -43, -85, 128, 128, -107, -21]
SAT_VALUES = [357, 434, 511, 588, 665, 741, 818]


def all_hits(data: bytes, pattern: bytes) -> list[int]:
    hits = []
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos < 0:
            return hits
        hits.append(pos)
        pos += 1


def context_hex(data: bytes, offset: int, before: int = 48, after: int = 96) -> dict:
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    return {
        "start": start,
        "end": end,
        "anchor_offset_within_context": offset - start,
        "hex": data[start:end].hex(),
    }


def packed_matrix_patterns(values: list[int]) -> dict[str, bytes]:
    return {
        "int16_le": struct.pack("<9h", *values),
        "int16_be": struct.pack(">9h", *values),
        "int32_le": struct.pack("<9i", *values),
        "int32_be": struct.pack(">9i", *values),
    }


def scan_u16_values(data: bytes, endian: str) -> dict[str, list[int]]:
    fmt = "<H" if endian == "le" else ">H"
    out: dict[str, list[int]] = {str(v): [] for v in SAT_VALUES}
    # Scan both aligned and unaligned 16-bit positions because the descriptor
    # payload alignment is not yet canonical.
    for off in range(0, len(data) - 1):
        value = struct.unpack_from(fmt, data, off)[0]
        key = str(value)
        if key in out:
            out[key].append(off)
    return out


def repeated_sat_field_candidates(data: bytes, endian: str) -> list[dict]:
    """Find positions where +6 and +8 hold the same known saturation field.

    Historical Category-42 notes recorded duplicated 10-bit fields at those
    payload-relative offsets. A hit is only a structural candidate, not proof of
    record start/category identity.
    """
    fmt = "<H" if endian == "le" else ">H"
    known = set(SAT_VALUES)
    out = []
    for start in range(0, max(0, len(data) - 10)):
        a = struct.unpack_from(fmt, data, start + 6)[0]
        b = struct.unpack_from(fmt, data, start + 8)[0]
        if a == b and a in known:
            out.append(
                {
                    "candidate_start": start,
                    "value": a,
                    "context": context_hex(data, start, 16, 64),
                }
            )
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("r2y", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    data = args.r2y.read_bytes()
    result = {
        "schema": "m11camera.r0.r2y_recorded_signature_probe.v1",
        "file": args.r2y.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signatures": {},
        "saturation_u16_occurrences": {},
        "category42_plus6_plus8_candidates": {},
        "notes": [
            "Literal signature matches are byte anchors only; category semantics require descriptor reconstruction.",
            "Category42 +6/+8 matches are heuristic candidate starts and may include false positives.",
        ],
    }

    for name, values in (("cc0", CC0), ("cc1", CC1), ("category24_ycc", YCC)):
        variants = {}
        for encoding, pattern in packed_matrix_patterns(values).items():
            hits = all_hits(data, pattern)
            variants[encoding] = {
                "pattern_hex": pattern.hex(),
                "hits": [
                    {"offset": off, "offset_hex": hex(off), "context": context_hex(data, off)}
                    for off in hits
                ],
            }
        result["signatures"][name] = variants

    for endian in ("le", "be"):
        occurrences = scan_u16_values(data, endian)
        # Keep full positions only when manageable; otherwise first/last + count.
        compact = {}
        for value, hits in occurrences.items():
            compact[value] = {
                "count": len(hits),
                "first_offsets": hits[:32],
                "last_offsets": hits[-8:] if len(hits) > 32 else [],
            }
        result["saturation_u16_occurrences"][endian] = compact

        cands = repeated_sat_field_candidates(data, endian)
        result["category42_plus6_plus8_candidates"][endian] = {
            "count": len(cands),
            "candidates": cands[:200],
            "truncated": len(cands) > 200,
        }

    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    else:
        print(text)

    for name, variants in result["signatures"].items():
        print(name)
        for encoding, item in variants.items():
            offsets = [h["offset_hex"] for h in item["hits"]]
            print(f"  {encoding}: {offsets}")
    for endian, item in result["category42_plus6_plus8_candidates"].items():
        print(f"category42 duplicated-field candidates {endian}: {item['count']}")


if __name__ == "__main__":
    main()
