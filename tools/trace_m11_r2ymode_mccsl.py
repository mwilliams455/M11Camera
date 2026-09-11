#!/usr/bin/env python3
"""Trace Leica M11-P R2YMODE/MCCSL placement control in the exact firmware image.

Public Socionext/Milbeaut headers place R2YMODE at R2Y-base + 0x94 and define
bit 4 (MCCSL) as the multi-axis colour-correction placement selector:
0 = MCC after CC0, 1 = MCC after gamma.

This probe is deliberately compiler-shape tolerant.  It finds A32 immediate
memory operations at the R2Y common-control neighbourhood (0x90/0x94/0x98),
clusters 0x94-anchored candidates, disassembles likely functions, reports
direct A32 BL callers, and highlights instructions that manipulate bit 4.

Evidence boundary: locating a setter and its bit-4 manipulation proves the
hardware/software mechanism.  It does NOT by itself prove Leica's runtime
MCCSL value; that requires tracing the value supplied by the caller/request.
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
MCCSL_MASK = 0x10


def a32_sdt_imm(w: int) -> tuple[bool, bool, bool, int] | None:
    """Decode A32 single-data-transfer immediate; return (load, up, byte, imm12)."""
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
        return None
    return bool((w >> 20) & 1), bool((w >> 23) & 1), bool((w >> 22) & 1), w & 0xFFF


def raw_hits(data: bytes) -> list[tuple[int, int, bool, bool]]:
    hits: list[tuple[int, int, bool, bool]] = []
    end = len(data) & ~3
    for p in range(0, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        dec = a32_sdt_imm(w)
        if dec is None:
            continue
        load, up, byte, imm = dec
        if up and imm in NEIGHBOUR_SET:
            hits.append((p, imm, load, byte))
    return hits


def cluster_hits(hits: list[tuple[int, int, bool, bool]], radius: int = 0x300) -> list[dict]:
    out: list[dict] = []
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
            local.append(hits[j])
            j += 1
        distinct = sorted({x[1] for x in local})
        r2ymode = [x for x in local if x[1] == R2YMODE_OFF]
        stores = [x for x in r2ymode if not x[2]]
        loads = [x for x in r2ymode if x[2]]
        # Prefer read/modify/write candidates, then candidates that also touch
        # adjacent R2Y common-control registers.
        score = len(distinct) * 15 + len(r2ymode) * 8 + len(stores) * 20 + len(loads) * 10
        if stores and loads:
            score += 80
        out.append({
            "centre": centre,
            "distinct": distinct,
            "r2ymode_count": len(r2ymode),
            "r2ymode_stores": len(stores),
            "r2ymode_loads": len(loads),
            "byte_accesses": sum(1 for x in r2ymode if x[3]),
            "score": score,
        })
    best: dict[int, dict] = {}
    for c in out:
        bucket = c["centre"] // 0x800
        if bucket not in best or c["score"] > best[bucket]["score"]:
            best[bucket] = c
    return sorted(best.values(), key=lambda x: x["score"], reverse=True)


def likely_entry(data: bytes, centre: int, max_back: int = 0x500) -> int:
    lo = max(0, centre - max_back) & ~3
    candidates = []
    for p in range(lo, centre + 1, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0xFFFF4000) == 0xE92D4000:  # push/stmdb sp!, {...,lr}
            candidates.append(p)
    return candidates[-1] if candidates else max(lo, centre - 0x100)


def bl_callers(data: bytes, target: int) -> list[int]:
    out = []
    end = len(data) & ~3
    for p in range(0, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 0x7) != 0x5 or ((w >> 24) & 1) == 0:
            continue
        imm24 = w & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 -= 1 << 24
        dest = (p + 8 + (imm24 << 2)) & 0xFFFFFFFF
        if dest == target:
            out.append(p)
    return out


def disasm(data: bytes, lo: int, hi: int):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return list(md.disasm(data[lo:hi], lo))


def bit4_lines(insns) -> list[str]:
    """Conservatively flag disassembly lines suggestive of MCCSL bit-4 handling."""
    out = []
    for i in insns:
        text = f"{i.mnemonic} {i.op_str}".lower()
        hit = False
        reasons = []
        # Common compiler forms: and/bic/orr/eor/tst with #0x10, or BFI/BFC
        # targeting bit 4.  Also retain explicit #4 shifts/bitfield positions.
        if re.search(r"#0x10\b|#16\b", text):
            hit = True; reasons.append("mask-0x10")
        if i.mnemonic.lower() in {"bfi", "bfc", "ubfx", "sbfx"} and re.search(r"#4\b", text):
            hit = True; reasons.append("bitfield-bit4")
        if i.mnemonic.lower() in {"lsl", "lsr", "asr"} and re.search(r"#4\b", text):
            hit = True; reasons.append("shift-4")
        if hit:
            out.append(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}    ; {','.join(reasons)}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--top", type=int, default=16)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    hits = raw_hits(data)
    ranked = cluster_hits(hits)
    lines = [
        "# M11-P R2YMODE / MCCSL placement trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- public R2YMODE displacement: `0x{R2YMODE_OFF:x}`",
        "- public MCCSL bit: `4` (`0x10`)",
        "- public semantics: `0 = MCC after CC0`, `1 = MCC after gamma`",
        f"- A32 +immediate accesses in R2Y common neighbourhood: `{len(hits)}`",
        f"- ranked 0x94-anchored candidate clusters: `{len(ranked)}`",
        "",
        "## Ranked candidates",
        "",
    ]

    for idx, c in enumerate(ranked[: args.top], 1):
        entry = likely_entry(data, c["centre"])
        callers = bl_callers(data, entry)
        insns = disasm(data, entry, min(len(data), c["centre"] + 0x180))
        flagged = bit4_lines(insns)
        lines += [
            f"### {idx}. candidate around `0x{c['centre']:08x}`",
            "",
            f"- estimated entry: `0x{entry:08x}`",
            f"- score: `{c['score']}`",
            f"- neighbourhood offsets observed: `{[hex(x) for x in c['distinct']]}`",
            f"- R2YMODE accesses: `{c['r2ymode_count']}` (loads `{c['r2ymode_loads']}`, stores `{c['r2ymode_stores']}`, byte `{c['byte_accesses']}`)",
            f"- direct A32 BL callers: `{len(callers)}`",
            f"- conservative bit-4/mask candidates in window: `{len(flagged)}`",
        ]
        for x in callers[:24]:
            lines.append(f"  - caller `0x{x:08x}`")
        if flagged:
            lines += ["", "Possible MCCSL manipulation:", "", "```asm", *flagged[:32], "```"]
        lines += ["", "Context:", "", "```asm"]
        lines += [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in insns[:280]]
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "A candidate that reads/writes R2YMODE and manipulates bit 4 is strong evidence for the Leica-side MCC placement setter. Static code alone does not establish whether Leica supplies 0 or 1 for the active still-photo path. The next step is to trace the candidate's caller/request value and close the runtime MCCSL state before changing renderer stage order.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
