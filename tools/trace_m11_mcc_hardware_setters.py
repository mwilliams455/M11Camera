#!/usr/bin/env python3
"""Locate Leica M11-P low-level F_R2Y.MCC hardware programmers.

Primary anchors:
* per-pipe register-base table: 0x43201224 (already closed by YC/MCCSL traces)
* Leica MCCSL writer selects the common R2Y block with perPipeBase +0x4000
* public Milbeaut R2YMODE is at 0xC094, placing that common block at 0xC000
* public Milbeaut MCC begins at 0x9000
  => with the same per-pipe origin (0x8000), MCC is perPipeBase +0x1000.

The scan ranks functions that reference the per-pipe base and select +0x1000,
then summarizes memory displacements against public MCC register landmarks.
No renderer arithmetic is inferred here.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
LO = 0x01B00000
HI = 0x01C00000

# Relative to MCC base (public Milbeaut address 0x9000).
LANDMARKS = {
    0x000: "MCYC",
    0x020: "MCB1AB",
    0x024: "MCB1CD",
    0x028: "MCB2AB",
    0x02C: "MCB2CD",
    0x030: "MCB3AB",
    0x034: "MCB3CD",
    0x038: "MCB4AB",
    0x03C: "MCB4CD",
    0x040: "MCID1",
    0x044: "MCID2",
    0x048: "MCID3",
    0x04C: "MCID4",
    0x080: "MCKA",
    0x100: "MCKB",
    0x180: "MCKC",
    0x200: "MCKD",
    0x280: "MCKE",
    0x300: "MCKF",
    0x380: "MCKG",
    0x400: "MCKH",
    0x480: "MCKI",
    0x500: "MCKJ",
    0x580: "MCKK",
    0x600: "MCKL",
    0x680: "MCLA",
    0x6C0: "MCLB",
    0x700: "MCLC",
    0x740: "MCLD",
    0x780: "MCLE",
    0x7C0: "MCLF",
    0x800: "MCLG",
    0x840: "MCLH",
    0x880: "MCLI",
    0x8C0: "MCLJ",
    0x900: "MCLK",
    0x940: "MCLL",
    0x980: "MCYCBALP",
}


def md(detail=False):
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = detail
    c.skipdata = True
    return c


def arm_mov_imm(word: int, kind: str) -> tuple[int, int] | None:
    # ARM A1 MOVW/MOVT: imm16 = imm4:imm12, Rd = bits 15:12.
    tag = word & 0x0FF00000
    want = 0x03000000 if kind == "movw" else 0x03400000
    if tag != want:
        return None
    rd = (word >> 12) & 0xF
    imm16 = (((word >> 16) & 0xF) << 12) | (word & 0xFFF)
    return rd, imm16


def find_base_hits(data: bytes) -> list[int]:
    hits = []
    stop = min(HI, len(data))
    for p in range(LO, stop - 4, 4):
        w = struct.unpack_from("<I", data, p)[0]
        dec = arm_mov_imm(w, "movw")
        if dec is None or dec[1] != 0x1224:
            continue
        rd = dec[0]
        for q in range(p + 4, min(p + 32, stop), 4):
            w2 = struct.unpack_from("<I", data, q)[0]
            dec2 = arm_mov_imm(w2, "movt")
            if dec2 is not None and dec2 == (rd, 0x4320):
                hits.append(p)
                break
    return hits


def find_function_window(data: bytes, hit: int) -> tuple[int, int]:
    start = max(LO, hit - 0x6000)
    stop = min(HI, hit + 0x10000)
    ins = list(md(False).disasm(data[start:stop], start))
    idx = next((i for i, x in enumerate(ins) if x.address == hit), None)
    if idx is None:
        return hit, min(HI, hit + 0x4000)
    fn = start
    for x in ins[:idx + 1]:
        if x.mnemonic == "push" and "lr" in x.op_str:
            fn = x.address
    end = min(HI, fn + 0x10000)
    for x in ins[idx + 1:]:
        if x.address < fn:
            continue
        if (x.mnemonic == "pop" and "pc" in x.op_str) or (x.mnemonic == "bx" and x.op_str.strip() == "lr"):
            end = x.address + 4
            break
    return fn, end


def parse_imm_add(op_str: str) -> int | None:
    m = re.search(r"#(0x[0-9a-f]+|[0-9]+)$", op_str)
    if not m:
        return None
    return int(m.group(1), 0)


def parse_mem_disp(op_str: str) -> list[int]:
    out = []
    for m in re.finditer(r"\[[^\]]+?,\s*#(0x[0-9a-f]+|[0-9]+)\]", op_str):
        out.append(int(m.group(1), 0))
    return out


def nearest_landmark(x: int) -> tuple[str, int] | None:
    best = min(LANDMARKS, key=lambda k: abs(x-k))
    delta = x - best
    if abs(delta) <= 0x7C:
        return LANDMARKS[best], delta
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    hits = find_base_hits(data)
    windows = {}
    for h in hits:
        fn, end = find_function_window(data, h)
        windows[(fn, end)] = windows.get((fn, end), []) + [h]

    rows = []
    for (fn, end), refs in sorted(windows.items()):
        ins = list(md(False).disasm(data[fn:end], fn))
        adds = []
        disps = []
        for x in ins:
            if x.mnemonic in ("add", "sub"):
                v = parse_imm_add(x.op_str)
                if v is not None:
                    adds.append((x.address, x.mnemonic, v, x.op_str))
            if x.mnemonic.startswith(("ldr", "str")):
                for d in parse_mem_disp(x.op_str):
                    disps.append((x.address, d, x.mnemonic, x.op_str))

        addvals = {v for _, _, v, _ in adds}
        bank_score = 0
        if 0x1000 in addvals:
            bank_score += 100
        if 0x4000 in addvals:
            bank_score += 5
        if 0x2000 in addvals:
            bank_score -= 15
        if 0x5000 in addvals:
            bank_score -= 5

        lm = []
        for addr, d, mn, ops in disps:
            n = nearest_landmark(d)
            if n:
                lm.append((addr, d, n[0], n[1], mn, ops))
        exact = [(addr, d, LANDMARKS[d], mn, ops) for addr, d, mn, ops in disps if d in LANDMARKS]
        score = bank_score + len({x[2] for x in exact}) * 8 + min(len(exact), 20)
        if score > 0:
            rows.append((score, fn, end, refs, adds, disps, exact, lm, ins))

    rows.sort(reverse=True)
    lines = [
        "# M11-P F_R2Y.MCC hardware-setter scan",
        "",
        f"- unpacked SHA-256: `{digest}`",
        f"- code range: `0x{LO:08x}..0x{HI:08x}`",
        f"- per-pipe base references found: `{len(hits)}`",
        f"- unique candidate functions: `{len(rows)}`",
        "- address closure: Leica common R2Y `+0x4000` == public `0xC000`; public MCC `0x9000` => target bank `perPipeBase +0x1000`",
        "",
        "## Ranked candidates",
        "",
        "| score | function | base refs | add immediates | exact MCC landmarks |",
        "| ---: | --- | ---: | --- | --- |",
    ]
    for score, fn, end, refs, adds, disps, exact, lm, ins in rows[:40]:
        addvals = sorted({v for _, _, v, _ in adds})
        names = sorted({x[2] for x in exact})
        lines.append(f"| {score} | `0x{fn:08x}..0x{end:08x}` | {len(refs)} | `{[hex(v) for v in addvals]}` | `{names}` |")

    for rank, row in enumerate(rows[:15], 1):
        score, fn, end, refs, adds, disps, exact, lm, ins = row
        lines += [
            "",
            f"## Candidate {rank}: `0x{fn:08x}..0x{end:08x}` score {score}",
            "",
            f"base refs: `{[hex(x) for x in refs]}`",
            f"add immediates: `{[(hex(a), m, hex(v), ops) for a,m,v,ops in adds if v >= 0x800]}`",
            f"exact landmarks: `{[(hex(a), hex(d), name) for a,d,name,_,_ in exact]}`",
            "",
            "### MCC-near accesses",
            "",
        ]
        for a0, d, name, delta, mn, ops in lm[:240]:
            lines.append(f"- `0x{a0:08x}` `{mn} {ops}` -> {name} `{delta:+#x}`")
        lines += ["", "### Base/bank instruction excerpts", "", "```asm"]
        for x in ins:
            if ("#0x1224" in x.op_str or "#0x4320" in x.op_str or "#0x1000" in x.op_str or "#0x2000" in x.op_str or "#0x4000" in x.op_str or "#0x5000" in x.op_str):
                lines.append(f"0x{x.address:08x}: {x.mnemonic} {x.op_str}")
        lines += ["```"]

    lines += [
        "",
        "## Interpretation boundary",
        "",
        "A candidate is only considered the Leica MCC hardware programmer if the per-pipe base selection and the public MCC register footprint agree. Function adjacency or category numbering alone is insufficient.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)

if __name__ == "__main__":
    main()
