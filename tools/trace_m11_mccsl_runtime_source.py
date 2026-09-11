#!/usr/bin/env python3
"""Trace the Leica M11-P runtime source for R2YMODE.MCCSL.

Closed anchors from the preceding exact-firmware trace:
  true R2Y common-control setter 0x01B1CDA4
  R2YMODE.MCCSL source byte [control + 0x67]
  bit-4 write 0x01B1D3A0..0x01B1D3AC
  sole direct caller 0x0176FE60

This focused pass follows that caller only, then uses a cheap raw A32 scan for
other +0x67 memory accesses. It avoids a full 16 MB Capstone-detail decode.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SETTER = 0x01B1CDA4
CALLSITE = 0x0176FE60
MCCSL_WRITE = 0x01B1D3A0
MCCSL_FIELD = 0x67
CODE_LO = 0x01000000
CODE_HI = 0x02000000


def u32(d: bytes, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]


def bl_target(p: int, w: int) -> int | None:
    if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 7) != 5 or ((w >> 24) & 1) == 0:
        return None
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (p + 8 + (imm << 2)) & 0xFFFFFFFF


def is_push_lr(w: int) -> bool:
    return (w & 0xFFFF4000) == 0xE92D4000


def md() -> Cs:
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    c.skipdata = True
    return c


def disasm(d: bytes, lo: int, hi: int):
    lo = max(0, lo) & ~3
    hi = min(len(d), hi) & ~3
    return list(md().disasm(d[lo:hi], lo))


def safe_ops(i):
    try:
        return i.operands
    except CsError:
        return ()


def rname(i, op) -> str | None:
    return i.reg_name(op.reg) if op.type == ARM_OP_REG else None


def fmt(i) -> str:
    return f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"


def find_entry(d: bytes, addr: int, max_back: int = 0x3000) -> int:
    lo = max(0, addr - max_back) & ~3
    candidates = [p for p in range(lo, addr + 1, 4) if is_push_lr(u32(d, p))]
    for e in reversed(candidates):
        reached = False
        for i in disasm(d, e, addr + 8):
            if i.address >= addr:
                reached = True
                break
            if i.address > e + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
                break
        if reached:
            return e
    return candidates[-1] if candidates else lo


def function_end(d: bytes, e: int, cap: int = 0x5000) -> int:
    for i in disasm(d, e, min(len(d), e + cap)):
        if i.address > e + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
            return i.address + 4
    return min(len(d), e + cap)


def writes_reg(i, reg: str) -> bool:
    ops = safe_ops(i)
    if not ops or i.mnemonic in ("cmp", "tst", "str", "strb", "strh", ".byte"):
        return False
    return rname(i, ops[0]) == reg


def last_writer(insns, idx: int, reg: str, window: int = 160):
    for j in range(idx - 1, max(-1, idx - window), -1):
        if writes_reg(insns[j], reg):
            return insns[j]
    return None


def mem_disp(i) -> int | None:
    for op in safe_ops(i):
        if op.type == ARM_OP_MEM:
            return int(op.mem.disp)
    return None


def raw_sdt_plus67_sites(d: bytes) -> list[int]:
    """A32 single-data-transfer immediate instructions with U=1, imm12=0x67."""
    out = []
    hi = min(len(d), CODE_HI) & ~3
    for p in range(CODE_LO, hi, 4):
        w = u32(d, p)
        cond = (w >> 28) & 0xF
        if cond == 0xF:
            continue
        if ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1):
            continue
        if ((w >> 23) & 1) != 1:
            continue
        if (w & 0xFFF) == MCCSL_FIELD:
            out.append(p)
    return out


def direct_callers(d: bytes, target: int) -> list[int]:
    out = []
    end = len(d) & ~3
    for p in range(0, end, 4):
        if bl_target(p, u32(d, p)) == target:
            out.append(p)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    d = a.unpacked.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    callers = direct_callers(d, SETTER)
    entry = find_entry(d, CALLSITE)
    end = function_end(d, entry)
    ins = disasm(d, entry, end)
    ci = next((n for n, i in enumerate(ins) if i.address == CALLSITE), None)
    if ci is None:
        raise RuntimeError("pinned callsite not inside recovered caller")

    r0w = last_writer(ins, ci, "r0")
    r1w = last_writer(ins, ci, "r1")
    local67 = [i for i in ins if mem_disp(i) == MCCSL_FIELD]
    stores_band = []
    for i in ins:
        ops = safe_ops(i)
        if i.mnemonic != "strb" or len(ops) < 2 or ops[1].type != ARM_OP_MEM:
            continue
        disp = int(ops[1].mem.disp)
        if 0x50 <= disp <= 0x75:
            stores_band.append(i)

    raw67 = raw_sdt_plus67_sites(d)
    ranked = []
    for p in raw67:
        score = 0
        if entry <= p < end:
            score += 100
        if abs(p - CALLSITE) <= 0x800:
            score += 60
        if abs(p - SETTER) <= 0x3000:
            score += 40
        # Cheap caller proximity check.
        for q in range(max(CODE_LO, p - 0x100), min(CODE_HI, p + 0x104), 4):
            if bl_target(q, u32(d, q)) == SETTER:
                score += 80
                break
        one = disasm(d, p, p + 4)
        text = fmt(one[0]) if one else f"0x{p:08x}: <decode failed>"
        ranked.append((score, p, text))
    ranked.sort(key=lambda x: (-x[0], x[1]))

    c0 = max(0, ci - 200)
    c1 = min(len(ins), ci + 100)
    lines = [
        "# M11-P MCCSL runtime source trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- true R2Y common-control setter: `0x{SETTER:08x}`",
        f"- MCCSL bit-4 write: `0x{MCCSL_WRITE:08x}`",
        f"- setter source byte: `[control + 0x{MCCSL_FIELD:02x}]`",
        f"- direct setter callers: `{[hex(x) for x in callers]}`",
        f"- direct callsite: `0x{CALLSITE:08x}`",
        f"- containing function: `0x{entry:08x}..0x{end:08x}`",
        "",
        "## Last argument writers before 0x0176FE60",
        "",
        f"- r0: `{fmt(r0w) if r0w else 'not recovered'}`",
        f"- r1: `{fmt(r1w) if r1w else 'not recovered'}`",
        "",
        "## +0x67 accesses in the direct caller",
        "",
    ]
    if local67:
        lines += ["```asm", *[fmt(i) for i in local67], "```"]
    else:
        lines.append("No literal +0x67 memory access in this containing function.")

    lines += ["", "## Byte stores in caller control-field band +0x50..+0x75", ""]
    if stores_band:
        lines += ["```asm", *[fmt(i) for i in stores_band], "```"]
    else:
        lines.append("No byte stores in this band.")

    lines += ["", "## Caller context around hardware-setter call", "", "```asm"]
    lines += [fmt(i) for i in ins[c0:c1]]
    lines += ["```", "", "## Whole containing caller", "", "```asm"]
    lines += [fmt(i) for i in ins]
    lines += ["```", "", "## Raw A32 +0x67 access sites ranked", ""]
    lines.append(f"Total single-data-transfer +0x67 sites in 0x01000000..0x02000000: `{len(raw67)}`")
    for n, (score, p, text) in enumerate(ranked[:120], 1):
        lines.append(f"{n}. score `{score}` — `{text}`")

    lines += [
        "",
        "## Decision boundary",
        "",
        "MCCSL setter semantics are closed. Leica still-photo placement becomes closed only when the upstream control source proves byte +0x67 is 0 or 1 on the relevant path. No renderer change is justified by setter identity alone.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
