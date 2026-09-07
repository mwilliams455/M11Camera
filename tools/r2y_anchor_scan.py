#!/usr/bin/env python3
"""Scan an extracted Leica M11/M11-P R2Y parameter binary for recorded anchors.

This tool deliberately does *not* assume the unknown descriptor-table layout.
It searches for byte-level signatures recovered from the August 2026 analysis
and reports candidate offsets under explicit signed-16-bit endian hypotheses.

The results are forensic leads only. A hit does not prove category identity,
record framing, stage order, or consumer semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


ANCHORS = {
    "cc0_q9": [495, -58, 63, 10, 601, -111, 49, -255, 705],
    "cc1_low_iso_q9": [1041, -372, -157, -117, 630, -1, -4, -78, 595],
    "category24_ycc": [77, 150, 29, -43, -85, 128, 128, -107, -21],
}

SAT_VALUES = [357, 434, 511, 588, 665, 741, 818]


@dataclass(frozen=True)
class Hit:
    anchor: str
    endian: str
    offset: int
    byte_length: int
    values: list[int]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pack_i16(values: Iterable[int], endian: str) -> bytes:
    prefix = "<" if endian == "little" else ">"
    vals = list(values)
    return struct.pack(prefix + ("h" * len(vals)), *vals)


def pack_u16(values: Iterable[int], endian: str) -> bytes:
    prefix = "<" if endian == "little" else ">"
    vals = list(values)
    return struct.pack(prefix + ("H" * len(vals)), *vals)


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + 1


def scan_matrix_anchors(data: bytes) -> list[Hit]:
    hits: list[Hit] = []
    for name, values in ANCHORS.items():
        for endian in ("little", "big"):
            needle = pack_i16(values, endian)
            for off in find_all(data, needle):
                hits.append(Hit(name, endian, off, len(needle), list(values)))
    return hits


def scan_saturation_runs(data: bytes) -> list[Hit]:
    """Search exact seven-state runs plus individual field values.

    The original work recorded Category 42 chroma-like fields at payload +6/+8,
    but descriptor framing is not yet reproduced. Exact seven-value runs are a
    strong lead; individual values are intentionally reported separately and
    should be treated as weak evidence.
    """
    hits: list[Hit] = []
    for endian in ("little", "big"):
        run = pack_u16(SAT_VALUES, endian)
        for off in find_all(data, run):
            hits.append(Hit("category42_sat_run", endian, off, len(run), SAT_VALUES))
        for value in SAT_VALUES:
            needle = pack_u16([value], endian)
            for off in find_all(data, needle):
                hits.append(Hit(f"category42_sat_value_{value}", endian, off, 2, [value]))
    return hits


def summarize(hits: list[Hit]) -> dict:
    grouped: dict[str, dict[str, list[int]]] = {}
    for hit in hits:
        grouped.setdefault(hit.anchor, {}).setdefault(hit.endian, []).append(hit.offset)
    return grouped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, help="Extracted r2y.bin or candidate parameter binary")
    ap.add_argument("--json", type=Path, help="Optional path for machine-readable report")
    ap.add_argument(
        "--include-weak-saturation-values",
        action="store_true",
        help="Also report every occurrence of individual recorded saturation values",
    )
    args = ap.parse_args()

    data = args.input.read_bytes()
    strong = scan_matrix_anchors(data)
    sat = scan_saturation_runs(data)
    if not args.include_weak_saturation_values:
        sat = [h for h in sat if h.anchor == "category42_sat_run"]
    hits = sorted(strong + sat, key=lambda h: (h.offset, h.anchor, h.endian))

    report = {
        "input": str(args.input),
        "size": len(data),
        "sha256": sha256_bytes(data),
        "evidence_warning": (
            "Byte-pattern hits are forensic leads only; they do not prove category identity, "
            "descriptor framing, stage order, or consumer semantics."
        ),
        "recorded_anchor_source": "M11P v0.3 prior findings recovered 2026-09-07",
        "hits": [asdict(h) for h in hits],
        "summary": summarize(hits),
    }

    print(f"input: {args.input}")
    print(f"size: {len(data)} bytes")
    print(f"sha256: {report['sha256']}")
    if not hits:
        print("no requested anchors found")
    else:
        for hit in hits:
            print(
                f"{hit.anchor:30s} endian={hit.endian:6s} "
                f"offset=0x{hit.offset:08X} len={hit.byte_length}"
            )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
