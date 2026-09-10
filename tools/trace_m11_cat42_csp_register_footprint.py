#!/usr/bin/env python3
"""Locate the Leica M11-P Milbeaut CSP setter by its register-write footprint.

This is deliberately compiler-shape tolerant.  The public Milbeaut CSP control
writes the late R2Y CSP register block at offsets 0x580..0x5ac after selecting
the R2Y pipe base.  Exact function-byte matching is fragile across compiler
revision/options; the ordered register displacement footprint is much harder to
change accidentally.

The probe scans the exact unpacked M11-P image for A32 immediate LDR/STR
instructions using those displacements, clusters nearby hits, disassembles only
high-scoring windows, estimates a conventional A32 function entry, and reports
direct BL callers.  It emits addresses/instructions only, never firmware bytes.

Evidence boundary: a strong footprint identifies a probable CSP register
programmer.  It does not by itself prove which Leica Category-42 state is
selected at runtime or reveal the hardware pixel equation.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CSP_OFFSETS = (0x580, 0x588, 0x58C, 0x590, 0x594, 0x598, 0x59C, 0x5A0, 0x5A4, 0x5A8, 0x5AC)
CSP_SET = set(CSP_OFFSETS)


def a32_sdt_imm(w: int) -> tuple[bool, bool, int] | None:
    """Decode A32 single-data-transfer immediate form; return (load, up, imm12)."""
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
        return None
    return bool((w >> 20) & 1), bool((w >> 23) & 1), w & 0xFFF


def raw_hits(data: bytes) -> list[tuple[int, int, bool]]:
    hits: list[tuple[int, int, bool]] = []
    end = len(data) & ~3
    for p in range(0, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        dec = a32_sdt_imm(w)
        if dec is None:
            continue
        load, up, imm = dec
        if up and imm in CSP_SET:
            hits.append((p, imm, load))
    return hits


def cluster_hits(hits: list[tuple[int, int, bool]], radius: int = 0x600) -> list[dict]:
    # Seed on a 0x580 access and score all CSP displacement accesses nearby.
    out: list[dict] = []
    positions = [h[0] for h in hits]
    j0 = 0
    for i, h in enumerate(hits):
        if h[1] != 0x580:
            continue
        centre = h[0]
        while j0 < len(hits) and hits[j0][0] < centre - radius:
            j0 += 1
        j = j0
        local = []
        while j < len(hits) and hits[j][0] <= centre + radius:
            local.append(hits[j])
            j += 1
        distinct = sorted({x[1] for x in local})
        stores = [x for x in local if not x[2]]
        store_distinct = sorted({x[1] for x in stores})
        ordered = []
        seen = set()
        for _, off, is_load in sorted(stores):
            if off not in seen:
                ordered.append(off); seen.add(off)
        prefix = 0
        for got, want in zip(ordered, CSP_OFFSETS):
            if got != want:
                break
            prefix += 1
        out.append({
            "centre": centre,
            "distinct": distinct,
            "store_distinct": store_distinct,
            "ordered_store_firsts": ordered,
            "prefix": prefix,
            "count": len(local),
            "score": len(store_distinct) * 20 + prefix * 15 + len(distinct),
        })
    # Deduplicate overlapping seeds by keeping the highest score per 0x1000 bucket.
    best: dict[int, dict] = {}
    for c in out:
        b = c["centre"] // 0x1000
        if b not in best or (c["score"], c["prefix"]) > (best[b]["score"], best[b]["prefix"]):
            best[b] = c
    return sorted(best.values(), key=lambda x: (x["score"], x["prefix"], len(x["store_distinct"])), reverse=True)


def disasm_lines(data: bytes, lo: int, hi: int) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return [f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in md.disasm(data[lo:hi], lo)]


def likely_entry(data: bytes, centre: int, max_back: int = 0x500) -> int:
    # A32 push including LR: STMDB sp!, {...,lr}; common mask E92D4xxx-ish.
    lo = max(0, centre - max_back) & ~3
    candidates = []
    for p in range(lo, centre + 1, 4):
        w = struct.unpack_from("<I", data, p)[0]
        # cond AL, block transfer, pre-decrement/writeback, Rn=sp, store, LR in reglist.
        if (w & 0xFFFF4000) == 0xE92D4000:
            candidates.append(p)
    return candidates[-1] if candidates else max(lo, centre - 0x100)


def bl_callers(data: bytes, target: int) -> list[int]:
    out = []
    end = len(data) & ~3
    for p in range(0, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        # A32 B/BL immediate, cond != NV, link bit set.
        if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 0x7) != 0x5 or ((w >> 24) & 1) == 0:
            continue
        imm24 = w & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 -= 1 << 24
        dest = (p + 8 + (imm24 << 2)) & 0xFFFFFFFF
        if dest == target:
            out.append(p)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    hits = raw_hits(data)
    ranked = cluster_hits(hits)
    lines = [
        "# M11-P Category-42 CSP register-footprint trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- A32 +immediate LDR/STR hits using CSP offsets: `{len(hits)}`",
        f"- clustered 0x580-seeded candidates: `{len(ranked)}`",
        "- target CSP register displacements: `" + ", ".join(hex(x) for x in CSP_OFFSETS) + "`",
        "",
        "## Ranked candidates",
        "",
    ]

    for idx, c in enumerate(ranked[: args.top], 1):
        entry = likely_entry(data, c["centre"])
        callers = bl_callers(data, entry)
        lines += [
            f"### {idx}. candidate around `0x{c['centre']:08x}`",
            "",
            f"- estimated entry: `0x{entry:08x}`",
            f"- score: `{c['score']}`; ordered-prefix length: `{c['prefix']}`",
            f"- distinct CSP offsets: `{[hex(x) for x in c['distinct']]}`",
            f"- distinct CSP store offsets: `{[hex(x) for x in c['store_distinct']]}`",
            f"- first-seen store order: `{[hex(x) for x in c['ordered_store_firsts']]}`",
            f"- direct A32 BL callers of estimated entry: `{len(callers)}`",
        ]
        for x in callers[:24]:
            lines.append(f"  - `0x{x:08x}`")
        lines += ["", "```asm"]
        # Keep artifact bounded: disassemble entry through centre+0x180.
        lines += disasm_lines(data, entry, min(len(data), c["centre"] + 0x180))[:260]
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "A top candidate covering most or all ordered CSP register displacements is strong evidence for the Leica Milbeaut CSP register programmer even when compiler-identical byte matching fails. Direct callers then become the next trace targets for Category-42 selector/runtime-state proof. The hardware CSYKY/chroma magnitude/piecewise pixel arithmetic remains open until separate evidence closes it.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
