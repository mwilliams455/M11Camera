#!/usr/bin/env python3
"""Trace the Leica M11-P runtime source for R2YMODE.MCCSL.

Prior hash-gated discovery pinned the true F_R2Y common-control programmer:
  setter entry 0x01B1CDA4
  MCCSL source byte [control + 0x67]
  R2YMODE bit 4 write at 0x01B1D3A0..0x01B1D3AC
  sole direct caller 0x0176FE60

This pass follows the caller-side r1/control pointer, reports all writes to the
+0x67 field in the containing function, and searches the canonical image for
other code accesses to +0x67 near calls into the same setter.  It deliberately
separates 'setter ABI closed' from 'still-photo runtime value closed'.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SETTER = 0x01B1CDA4
CALLSITE = 0x0176FE60
MCCSL_WRITE = 0x01B1D3A0
MCCSL_FIELD = 0x67
BASE_TABLE = 0x43201224


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


def find_entry(d: bytes, addr: int, max_back: int = 0x3000) -> int:
    lo = max(0, addr - max_back) & ~3
    candidates = []
    for p in range(lo, addr + 1, 4):
        if is_push_lr(u32(d, p)):
            candidates.append(p)
    if not candidates:
        return lo
    # Prefer a candidate whose decoded function reaches the callsite without an
    # earlier return.  Walk newest-to-oldest.
    for e in reversed(candidates):
        for i in disasm(d, e, addr + 8):
            if i.address >= addr:
                return e
            if i.address > e + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
                break
    return candidates[-1]


def function_end(d: bytes, e: int, cap: int = 0x5000) -> int:
    for i in disasm(d, e, min(len(d), e + cap)):
        if i.address > e + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
            return i.address + 4
    return min(len(d), e + cap)


def rname(i, op) -> str | None:
    return i.reg_name(op.reg) if op.type == ARM_OP_REG else None


def imm(i, op) -> int | None:
    return int(op.imm) if op.type == ARM_OP_IMM else None


def fmt(i) -> str:
    return f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"


def accesses_field(i, disp: int) -> bool:
    for op in i.operands:
        if op.type == ARM_OP_MEM and int(op.mem.disp) == disp:
            return True
    return False


def writes_register(i, reg: str) -> bool:
    if not i.operands:
        return False
    return rname(i, i.operands[0]) == reg and i.mnemonic not in ("cmp", "tst", "str", "strb", "strh")


def last_writers(insns, idx: int, regs=("r0", "r1"), window: int = 100):
    out = {}
    for reg in regs:
        for j in range(idx - 1, max(-1, idx - window), -1):
            if writes_register(insns[j], reg):
                out[reg] = insns[j]
                break
    return out


def direct_callers(d: bytes, target: int) -> list[int]:
    out = []
    end = len(d) & ~3
    for p in range(0, end, 4):
        if bl_target(p, u32(d, p)) == target:
            out.append(p)
    return out


def mov_abs_before(insns, idx: int, reg: str, window: int = 40) -> int | None:
    lo = max(0, idx - window)
    val = None
    for j in range(lo, idx):
        i = insns[j]
        if not i.operands or rname(i, i.operands[0]) != reg:
            continue
        if i.mnemonic in ("mov", "movw") and len(i.operands) >= 2:
            x = imm(i, i.operands[1])
            if x is not None:
                val = x & 0xFFFF
        elif i.mnemonic == "movt" and len(i.operands) >= 2 and val is not None:
            x = imm(i, i.operands[1])
            if x is not None:
                val |= (x & 0xFFFF) << 16
    return val


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
    caller_entry = find_entry(d, CALLSITE)
    caller_end = function_end(d, caller_entry)
    ins = disasm(d, caller_entry, caller_end)
    ci = next((n for n, i in enumerate(ins) if i.address == CALLSITE), None)
    if ci is None:
        raise RuntimeError("pinned callsite not inside recovered caller")
    writers = last_writers(ins, ci, ("r0", "r1"), 120)

    # Every literal +0x67 memory access in the containing wrapper is worth
    # auditing because one may initialize/copy the field ultimately consumed by
    # the hardware setter.
    field_accesses = [i for i in ins if accesses_field(i, MCCSL_FIELD)]

    # Also collect nearby byte stores with small offsets; these reveal whether
    # the caller builds a compact control structure field-by-field.
    nearby_byte_stores = []
    for i in ins:
        if i.mnemonic != "strb" or len(i.operands) < 2 or i.operands[1].type != ARM_OP_MEM:
            continue
        disp = int(i.operands[1].mem.disp)
        if 0x50 <= disp <= 0x75:
            nearby_byte_stores.append(i)

    # Search code for accesses to +0x67 and rank contexts that also contain the
    # pinned base-table literal or a direct call to the setter. This is not used
    # as a substitute for exact caller tracing; it helps find upstream builders.
    global_field_sites = []
    code_lo, code_hi = 0x01000000, min(len(d), 0x02000000)
    all_ins = disasm(d, code_lo, code_hi)
    for n, i in enumerate(all_ins):
        if not accesses_field(i, MCCSL_FIELD):
            continue
        score = 0
        lo = max(0, n - 32); hi = min(len(all_ins), n + 33)
        win = all_ins[lo:hi]
        if any(bl_target(x.address, u32(d, x.address)) == SETTER for x in win):
            score += 100
        # Detect 0x43201224 construction in the local window.
        for k, x in enumerate(win):
            if x.mnemonic == "movw" and len(x.operands) >= 2:
                xv = imm(x, x.operands[1])
                if xv == (BASE_TABLE & 0xFFFF):
                    for y in win[k + 1:k + 6]:
                        if y.mnemonic == "movt" and len(y.operands) >= 2 and rname(y, y.operands[0]) == rname(x, x.operands[0]):
                            yv = imm(y, y.operands[1])
                            if yv == ((BASE_TABLE >> 16) & 0xFFFF):
                                score += 50
                                break
        if i.mnemonic.startswith("str"):
            score += 10
        global_field_sites.append((score, i.address, i))
    global_field_sites.sort(reverse=True, key=lambda x: (x[0], -x[1]))

    lines = [
        "# M11-P MCCSL runtime source trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- pinned true R2Y common-control setter: `0x{SETTER:08x}`",
        f"- pinned MCCSL hardware write: `0x{MCCSL_WRITE:08x}`",
        f"- setter source field: `[control + 0x{MCCSL_FIELD:02x}]`",
        f"- direct callers of setter: `{[hex(x) for x in callers]}`",
        f"- pinned direct caller: `0x{CALLSITE:08x}`",
        f"- recovered containing function: `0x{caller_entry:08x}..0x{caller_end:08x}`",
        "",
        "## Last argument writers before the setter call",
        "",
    ]
    for reg in ("r0", "r1"):
        i = writers.get(reg)
        lines.append(f"- {reg}: `{fmt(i) if i else 'not recovered'}`")

    lines += ["", "## +0x67 accesses inside the direct caller", ""]
    if field_accesses:
        lines += ["```asm", *[fmt(i) for i in field_accesses], "```"]
    else:
        lines.append("No direct `+0x67` access in the containing caller function.")

    lines += ["", "## Nearby control-byte stores (+0x50..+0x75) inside direct caller", ""]
    if nearby_byte_stores:
        lines += ["```asm", *[fmt(i) for i in nearby_byte_stores], "```"]
    else:
        lines.append("No byte stores in this offset band.")

    # Caller context centered around the call.
    c0 = max(0, ci - 160); c1 = min(len(ins), ci + 81)
    lines += ["", "## Direct caller context around setter call", "", "```asm"]
    lines += [fmt(i) for i in ins[c0:c1]]
    lines += ["```", ""]

    lines += ["## Whole direct caller (audit)", "", "```asm"]
    lines += [fmt(i) for i in ins]
    lines += ["```", ""]

    lines += ["## Global +0x67 access candidates", ""]
    for rank, (score, addr, i) in enumerate(global_field_sites[:80], 1):
        lines.append(f"{rank}. score `{score}` — `{fmt(i)}`")

    lines += [
        "",
        "## Decision boundary",
        "",
        "The setter ABI is closed: R2YMODE.MCCSL bit 4 is sourced from control byte +0x67. The Leica still-photo runtime state becomes closed only when the caller/upstream builder proves that byte is 0 or 1 for the relevant path. Do not alter renderer MCC placement from the setter alone.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
