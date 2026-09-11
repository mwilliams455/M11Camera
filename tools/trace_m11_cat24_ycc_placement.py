#!/usr/bin/env python3
"""Trace Leica M11-P Category-24/YCC placement against the known Cat42/CSP block.

The pinned public Milbeaut ImageMacro source gives two independent hardware
footprints in the same F_R2Y register bank:

* YC convert (`im_r2y_ctrl2_yc_convert`): offsets 0x100..0x110 plus YBLEND 0x120.
* Chroma suppress (`im_r2y_ctrl3_chroma_suppress`): offsets 0x580..0x5ac.

This probe searches the exact hash-gated M11-P image for compiler-tolerant A32
single-data-transfer footprints for both blocks, estimates conventional function
entries, reports direct BL callers, and looks for higher-level functions that call
both top candidates.  It emits addresses/instructions only, never firmware bytes.

Evidence boundary: register displacement order is hardware-layout evidence, not
by itself pixel-flow proof.  A shared software caller can establish configuration
relationship/order, but configuration order is still not automatically pixel
order.  Pixel-stage closure should therefore combine this trace with the public
block semantics (YC conversion vs chroma suppression) and generated register
layout rather than rely on numeric addresses alone.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"

# Pinned public Milbeaut CtrlRdmaYccAddr / F_R2Y.YC footprint.
YCC_OFFSETS = (0x100, 0x104, 0x108, 0x10C, 0x110, 0x120)
# Existing closed Cat42/CSP footprint, retained here for side-by-side placement.
CSP_OFFSETS = (0x580, 0x588, 0x58C, 0x590, 0x594, 0x598, 0x59C, 0x5A0, 0x5A4, 0x5A8, 0x5AC)
KNOWN_CSP_ENTRY = 0x01B68B80


def a32_sdt_imm(w: int) -> tuple[bool, bool, int] | None:
    """Decode A32 single-data-transfer immediate; return (load, up, imm12)."""
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
        return None
    return bool((w >> 20) & 1), bool((w >> 23) & 1), w & 0xFFF


def raw_hits(data: bytes, offsets: tuple[int, ...]) -> list[tuple[int, int, bool]]:
    wanted = set(offsets)
    out: list[tuple[int, int, bool]] = []
    for p in range(0, len(data) & ~3, 4):
        w = struct.unpack_from("<I", data, p)[0]
        dec = a32_sdt_imm(w)
        if dec is None:
            continue
        load, up, imm = dec
        if up and imm in wanted:
            out.append((p, imm, load))
    return out


def cluster_hits(
    hits: list[tuple[int, int, bool]],
    offsets: tuple[int, ...],
    radius: int = 0x500,
) -> list[dict]:
    """Rank local clusters by distinct stores and ordered first-store prefix."""
    seed = offsets[0]
    out: list[dict] = []
    j0 = 0
    for h in hits:
        if h[1] != seed:
            continue
        centre = h[0]
        while j0 < len(hits) and hits[j0][0] < centre - radius:
            j0 += 1
        j = j0
        local: list[tuple[int, int, bool]] = []
        while j < len(hits) and hits[j][0] <= centre + radius:
            local.append(hits[j])
            j += 1
        stores = [x for x in local if not x[2]]
        distinct = sorted({x[1] for x in local})
        store_distinct = sorted({x[1] for x in stores})
        first_order: list[int] = []
        seen: set[int] = set()
        for _, off, _ in sorted(stores):
            if off not in seen:
                first_order.append(off)
                seen.add(off)
        prefix = 0
        for got, want in zip(first_order, offsets):
            if got != want:
                break
            prefix += 1
        coverage = len(set(store_distinct) & set(offsets))
        out.append(
            {
                "centre": centre,
                "distinct": distinct,
                "store_distinct": store_distinct,
                "first_order": first_order,
                "prefix": prefix,
                "coverage": coverage,
                "count": len(local),
                "score": coverage * 30 + prefix * 20 + len(distinct),
            }
        )

    # Keep the strongest seed per 0x1000 region to avoid near-duplicate windows.
    best: dict[int, dict] = {}
    for c in out:
        bucket = c["centre"] // 0x1000
        if bucket not in best or (c["score"], c["prefix"]) > (
            best[bucket]["score"],
            best[bucket]["prefix"],
        ):
            best[bucket] = c
    return sorted(
        best.values(),
        key=lambda x: (x["score"], x["coverage"], x["prefix"]),
        reverse=True,
    )


def likely_entry(data: bytes, centre: int, max_back: int = 0x600) -> int:
    """Find nearest conventional A32 push {...,lr} before a candidate."""
    lo = max(0, centre - max_back) & ~3
    candidates: list[int] = []
    for p in range(lo, centre + 1, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0xFFFF4000) == 0xE92D4000:
            candidates.append(p)
    return candidates[-1] if candidates else max(lo, centre - 0x100)


def a32_bl_target(p: int, w: int) -> int | None:
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 25) & 0x7) != 0x5 or ((w >> 24) & 1) == 0:
        return None
    imm24 = w & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (p + 8 + (imm24 << 2)) & 0xFFFFFFFF


def bl_callers(data: bytes, target: int) -> list[int]:
    out: list[int] = []
    for p in range(0, len(data) & ~3, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if a32_bl_target(p, w) == target:
            out.append(p)
    return out


def enclosing_entries(data: bytes, calls: list[int]) -> dict[int, list[int]]:
    grouped: dict[int, list[int]] = {}
    for call in calls:
        entry = likely_entry(data, call, max_back=0x900)
        grouped.setdefault(entry, []).append(call)
    return grouped


def disasm_lines(data: bytes, lo: int, hi: int) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return [f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in md.disasm(data[lo:hi], lo)]


def emit_ranked(
    lines: list[str],
    title: str,
    data: bytes,
    ranked: list[dict],
    offsets: tuple[int, ...],
    top: int,
) -> None:
    lines += [f"## {title}", "", "Target offsets: `" + ", ".join(hex(x) for x in offsets) + "`", ""]
    for idx, c in enumerate(ranked[:top], 1):
        entry = likely_entry(data, c["centre"])
        callers = bl_callers(data, entry)
        lines += [
            f"### {idx}. candidate around `0x{c['centre']:08x}`",
            "",
            f"- estimated entry: `0x{entry:08x}`",
            f"- score: `{c['score']}`; coverage: `{c['coverage']}/{len(offsets)}`; ordered-prefix: `{c['prefix']}`",
            f"- distinct stores: `{[hex(x) for x in c['store_distinct']]}`",
            f"- first-seen store order: `{[hex(x) for x in c['first_order']]}`",
            f"- direct BL callers: `{len(callers)}`",
        ]
        for x in callers[:20]:
            lines.append(f"  - `0x{x:08x}`")
        lines += ["", "```asm"]
        lines += disasm_lines(data, entry, min(len(data), c["centre"] + 0x160))[:220]
        lines += ["```", ""]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    ycc_hits = raw_hits(data, YCC_OFFSETS)
    csp_hits = raw_hits(data, CSP_OFFSETS)
    ycc_ranked = cluster_hits(ycc_hits, YCC_OFFSETS)
    csp_ranked = cluster_hits(csp_hits, CSP_OFFSETS, radius=0x600)

    lines = [
        "# M11-P Category-24 YCC / Cat42 CSP placement trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- YC immediate-offset hits: `{len(ycc_hits)}`; ranked clusters: `{len(ycc_ranked)}`",
        f"- CSP immediate-offset hits: `{len(csp_hits)}`; ranked clusters: `{len(csp_ranked)}`",
        f"- previously closed CSP Leica entry anchor: `0x{KNOWN_CSP_ENTRY:08x}`",
        "",
    ]

    emit_ranked(lines, "YC/YCC footprint candidates", data, ycc_ranked, YCC_OFFSETS, args.top)
    emit_ranked(lines, "CSP footprint candidates", data, csp_ranked, CSP_OFFSETS, min(args.top, 5))

    lines += ["## Cross-stage caller relationship", ""]
    if ycc_ranked and csp_ranked:
        y_entry = likely_entry(data, ycc_ranked[0]["centre"])
        c_entry = likely_entry(data, csp_ranked[0]["centre"])
        y_calls = bl_callers(data, y_entry)
        c_calls = bl_callers(data, c_entry)
        y_parents = enclosing_entries(data, y_calls)
        c_parents = enclosing_entries(data, c_calls)
        common = sorted(set(y_parents) & set(c_parents))
        lines += [
            f"- top YC entry: `0x{y_entry:08x}`",
            f"- top CSP entry: `0x{c_entry:08x}`",
            f"- top CSP entry matches prior anchor: `{c_entry == KNOWN_CSP_ENTRY}`",
            f"- estimated higher-level entries containing direct calls to both: `{len(common)}`",
        ]
        for parent in common[:20]:
            lines += [
                f"  - parent `0x{parent:08x}`: YC calls `{[hex(x) for x in y_parents[parent]]}`, CSP calls `{[hex(x) for x in c_parents[parent]]}`",
            ]
        if common:
            lines += ["", "### Common-parent disassembly", ""]
            for parent in common[:4]:
                lines += [f"#### `0x{parent:08x}`", "", "```asm"]
                lines += disasm_lines(data, parent, min(len(data), parent + 0x500))[:320]
                lines += ["```", ""]
    else:
        lines.append("No ranked candidate pair was available for cross-stage analysis.")

    lines += [
        "",
        "## Interpretation boundary",
        "",
        "The YC footprint comes from the pinned public `CtrlRdmaYccAddr`/`F_R2Y.YC` hardware interface (3x3 YC conversion coefficients plus YBLEND). The CSP footprint is the independently closed late `F_R2Y.CSP` block used by Category-42. Numeric register ordering alone is not pixel-flow proof. A high-coverage Leica YC programmer plus a software relationship to the known CSP programmer narrows Category-24 placement; final renderer placement should additionally respect the public block semantics and any caller/configuration ordering exposed above.",
        "",
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
