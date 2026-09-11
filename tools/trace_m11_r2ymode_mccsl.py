#!/usr/bin/env python3
"""Trace Leica M11-P R2YMODE/MCCSL placement control in the exact firmware image.

Public Socionext/Milbeaut headers place R2YMODE at R2Y-base + 0x94 and define
bit 4 (MCCSL) as the multi-axis colour-correction placement selector:
0 = MCC after CC0, 1 = MCC after gamma.

This pass locates candidate R2Y common-control setters by their 0x88..0x98
register neighbourhood, then performs ONE full-firmware direct-BL pass for all
ranked candidate entries.  The previous draft rescanned the 97.6 MB image once
per candidate and was unnecessarily expensive.

Evidence boundary: setter identity does not by itself prove Leica's runtime
MCCSL state; the supplied value must be traced through the caller/control
structure before renderer stage order is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
R2YMODE_OFF = 0x94
NEIGHBOUR_OFFSETS = (0x88, 0x8C, 0x90, 0x94, 0x98)
NEIGHBOUR_SET = set(NEIGHBOUR_OFFSETS)


def a32_sdt_imm(w: int) -> tuple[bool, bool, bool, int] | None:
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
        return None
    return bool((w >> 20) & 1), bool((w >> 23) & 1), bool((w >> 22) & 1), w & 0xFFF


def raw_hits(data: bytes) -> list[tuple[int, int, bool, bool]]:
    hits = []
    end = len(data) & ~3
    for p in range(0, end, 4):
        dec = a32_sdt_imm(struct.unpack_from("<I", data, p)[0])
        if dec is None:
            continue
        load, up, byte, imm = dec
        if up and imm in NEIGHBOUR_SET:
            hits.append((p, imm, load, byte))
    return hits


def cluster_hits(hits: list[tuple[int, int, bool, bool]], radius: int = 0x300) -> list[dict]:
    out = []
    j0 = 0
    for h in hits:
        if h[1] != R2YMODE_OFF:
            continue
        centre = h[0]
        while j0 < len(hits) and hits[j0][0] < centre - radius:
            j0 += 1
        j = j0
        local = []
        while j < len(hits) and hits[j][0] <= centre + radius:
            local.append(hits[j]); j += 1
        distinct = sorted({x[1] for x in local})
        mode = [x for x in local if x[1] == R2YMODE_OFF]
        stores = [x for x in mode if not x[2]]
        loads = [x for x in mode if x[2]]
        score = len(distinct) * 15 + len(mode) * 8 + len(stores) * 20 + len(loads) * 10
        if stores and loads:
            score += 80
        if len(distinct) >= 4:
            score += 40
        out.append({
            "centre": centre,
            "distinct": distinct,
            "r2ymode_count": len(mode),
            "r2ymode_stores": len(stores),
            "r2ymode_loads": len(loads),
            "byte_accesses": sum(1 for x in mode if x[3]),
            "score": score,
        })
    best = {}
    for c in out:
        bucket = c["centre"] // 0x800
        if bucket not in best or c["score"] > best[bucket]["score"]:
            best[bucket] = c
    return sorted(best.values(), key=lambda x: x["score"], reverse=True)


def is_push_lr(w: int) -> bool:
    return (w & 0xFFFF4000) == 0xE92D4000


def likely_entry(data: bytes, centre: int, max_back: int = 0x700) -> int:
    lo = max(0, centre - max_back) & ~3
    candidates = []
    for p in range(lo, centre + 1, 4):
        if is_push_lr(struct.unpack_from("<I", data, p)[0]):
            candidates.append(p)
    return candidates[-1] if candidates else max(lo, centre - 0x100)


def bl_target(p: int, w: int) -> int | None:
    if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 7) != 5 or ((w >> 24) & 1) == 0:
        return None
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (p + 8 + (imm << 2)) & 0xFFFFFFFF


def bl_callers_for_targets(data: bytes, targets: set[int]) -> dict[int, list[int]]:
    out = {x: [] for x in targets}
    end = len(data) & ~3
    for p in range(0, end, 4):
        t = bl_target(p, struct.unpack_from("<I", data, p)[0])
        if t in out:
            out[t].append(p)
    return out


def disasm(data: bytes, lo: int, hi: int):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return list(md.disasm(data[lo:hi], lo))


def function_end(data: bytes, entry: int, cap: int = 0x1800) -> int:
    for i in disasm(data, entry, min(len(data), entry + cap)):
        if i.address > entry + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
            return i.address + 4
    return min(len(data), entry + cap)


def bit4_lines(insns) -> list[str]:
    out = []
    for i in insns:
        text = f"{i.mnemonic} {i.op_str}".lower()
        reasons = []
        if re.search(r"#0x10\b|#16\b", text):
            reasons.append("mask-0x10")
        if i.mnemonic.lower() in {"bfi", "bfc", "ubfx", "sbfx"} and re.search(r"#4\b", text):
            reasons.append("bitfield-bit4")
        if i.mnemonic.lower() in {"lsl", "lsr", "asr"} and re.search(r"#4\b", text):
            reasons.append("shift-4")
        if reasons:
            out.append(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}    ; {','.join(reasons)}")
    return out


def mode_lines(insns) -> list[str]:
    out = []
    for i in insns:
        text = f"{i.mnemonic} {i.op_str}".lower()
        if re.search(r"#0x94\b|#148\b", text):
            out.append(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    hits = raw_hits(data)
    ranked = cluster_hits(hits)[:args.top]
    entries = [likely_entry(data, c["centre"]) for c in ranked]
    callers = bl_callers_for_targets(data, set(entries))

    lines = [
        "# M11-P R2YMODE / MCCSL placement trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        "- public R2YMODE displacement: `0x94`",
        "- public MCCSL bit: `4` (`0x10`)",
        "- public semantics: `0 = MCC after CC0`, `1 = MCC after gamma`",
        f"- A32 +immediate accesses in R2Y common neighbourhood: `{len(hits)}`",
        f"- ranked candidates emitted: `{len(ranked)}`",
        "- direct caller search: one full-firmware pass for all candidates",
        "",
        "## Ranked candidates",
        "",
    ]
    for idx, c in enumerate(ranked, 1):
        entry = entries[idx - 1]
        end = function_end(data, entry)
        insns = disasm(data, entry, end)
        flagged = bit4_lines(insns)
        modes = mode_lines(insns)
        cs = callers.get(entry, [])
        lines += [
            f"### {idx}. candidate around `0x{c['centre']:08x}`",
            "",
            f"- estimated entry: `0x{entry:08x}`",
            f"- estimated end: `0x{end:08x}`",
            f"- score: `{c['score']}`",
            f"- neighbourhood offsets: `{[hex(x) for x in c['distinct']]}`",
            f"- R2YMODE accesses in cluster: `{c['r2ymode_count']}` (loads `{c['r2ymode_loads']}`, stores `{c['r2ymode_stores']}`)",
            f"- direct A32 BL callers: `{len(cs)}`",
            f"- explicit 0x94 lines in function: `{len(modes)}`",
            f"- bit-4/mask candidates: `{len(flagged)}`",
        ]
        for x in cs[:32]:
            lines.append(f"  - caller `0x{x:08x}`")
        if modes:
            lines += ["", "R2YMODE-offset lines:", "", "```asm", *modes[:32], "```"]
        if flagged:
            lines += ["", "Possible MCCSL manipulation:", "", "```asm", *flagged[:48], "```"]
        lines += ["", "Function context:", "", "```asm"]
        lines += [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in insns[:420]]
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "A candidate that genuinely accesses R2Y-base+0x94 and manipulates bit 4 can identify the Leica MCC placement setter. The still-photo runtime state remains open until the value source/caller is traced. Do not alter renderer MCC placement from this discovery pass alone.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
