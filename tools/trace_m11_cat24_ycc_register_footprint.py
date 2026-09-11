#!/usr/bin/env python3
"""Locate Leica M11-P YC-convert programmers by the Milbeaut register footprint.

Public Milbeaut R2yCtrlYcc writes five packed YC coefficient registers at R2Y
+0x100,+0x104,+0x108,+0x10c,+0x110 and YBLEND at +0x120.  Category 24 contains
exactly the nine signed YC coefficients.  This scanner is compiler-shape
tolerant: it ranks A32 code regions using those immediate register offsets,
estimates function entries and reports direct BL callers.

The address footprint is independent evidence from the exact-GCC object matcher.
It identifies a probable hardware programmer, not the pixel-stage order by
itself and not Leica runtime selection semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
YCC_OFFSETS = (0x100, 0x104, 0x108, 0x10C, 0x110, 0x120)
YCC_SET = set(YCC_OFFSETS)


def a32_sdt_imm(w: int) -> tuple[bool, bool, int] | None:
    if ((w >> 28) & 0xF) == 0xF or ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
        return None
    return bool((w >> 20) & 1), bool((w >> 23) & 1), w & 0xFFF


def raw_hits(data: bytes) -> list[tuple[int, int, bool]]:
    out = []
    for p in range(0, len(data) & ~3, 4):
        dec = a32_sdt_imm(struct.unpack_from("<I", data, p)[0])
        if dec is None:
            continue
        load, up, imm = dec
        if up and imm in YCC_SET:
            out.append((p, imm, load))
    return out


def cluster_hits(hits: list[tuple[int, int, bool]], radius: int = 0x500) -> list[dict]:
    ranked = []
    j0 = 0
    for h in hits:
        if h[1] != 0x100:
            continue
        centre = h[0]
        while j0 < len(hits) and hits[j0][0] < centre - radius:
            j0 += 1
        j = j0
        local = []
        while j < len(hits) and hits[j][0] <= centre + radius:
            local.append(hits[j]); j += 1
        stores = [x for x in local if not x[2]]
        distinct = sorted({x[1] for x in local})
        store_distinct = sorted({x[1] for x in stores})
        ordered, seen = [], set()
        for _, off, _ in sorted(stores):
            if off not in seen:
                ordered.append(off); seen.add(off)
        prefix = 0
        for got, want in zip(ordered, YCC_OFFSETS):
            if got != want:
                break
            prefix += 1
        score = len(store_distinct) * 20 + prefix * 15 + len(distinct)
        ranked.append({
            "centre": centre,
            "distinct": distinct,
            "store_distinct": store_distinct,
            "ordered": ordered,
            "prefix": prefix,
            "score": score,
        })
    best = {}
    for row in ranked:
        bucket = row["centre"] // 0x1000
        if bucket not in best or (row["score"], row["prefix"]) > (best[bucket]["score"], best[bucket]["prefix"]):
            best[bucket] = row
    return sorted(best.values(), key=lambda x: (x["score"], x["prefix"], len(x["store_distinct"])), reverse=True)


def likely_entry(data: bytes, centre: int, max_back: int = 0x500) -> int:
    lo = max(0, centre - max_back) & ~3
    candidates = []
    for p in range(lo, centre + 1, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0xFFFF4000) == 0xE92D4000:
            candidates.append(p)
    return candidates[-1] if candidates else max(lo, centre - 0x100)


def bl_callers(data: bytes, target: int) -> list[int]:
    out = []
    for p in range(0, len(data) & ~3, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 0x7) != 0x5 or ((w >> 24) & 1) == 0:
            continue
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 1 << 24
        if ((p + 8 + (imm << 2)) & 0xFFFFFFFF) == target:
            out.append(p)
    return out


def disasm_lines(data: bytes, lo: int, hi: int) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return [f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in md.disasm(data[lo:hi], lo)]


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
        "# M11-P Category-24 YC-convert register-footprint trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- A32 +immediate LDR/STR hits using YCC offsets: `{len(hits)}`",
        f"- clustered 0x100-seeded candidates: `{len(ranked)}`",
        "- target offsets: `" + ", ".join(hex(x) for x in YCC_OFFSETS) + "`",
        "- public register topology: YC at R2Y +0x100..+0x110; YBLEND at +0x120",
        "",
        "## Ranked candidates",
        "",
    ]
    for n, row in enumerate(ranked[:args.top], 1):
        entry = likely_entry(data, row["centre"])
        callers = bl_callers(data, entry)
        lines += [
            f"### {n}. candidate around `0x{row['centre']:08x}`",
            "",
            f"- estimated entry: `0x{entry:08x}`",
            f"- score: `{row['score']}`; ordered-prefix length: `{row['prefix']}`",
            f"- distinct YCC offsets: `{[hex(x) for x in row['distinct']]}`",
            f"- distinct YCC store offsets: `{[hex(x) for x in row['store_distinct']]}`",
            f"- first-seen store order: `{[hex(x) for x in row['ordered']]}`",
            f"- direct A32 BL callers of estimated entry: `{len(callers)}`",
        ]
        for caller in callers[:24]:
            lines.append(f"  - `0x{caller:08x}`")
        lines += ["", "```asm"]
        lines += disasm_lines(data, entry, min(len(data), row["centre"] + 0x180))[:260]
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "A candidate covering the ordered YC/YBLEND register displacement family is strong evidence for a Leica YC-convert programmer. Exact-GCC convergence on the same region is the preferred independent confirmation. Register address order alone is not promoted to pixel-stage order.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
