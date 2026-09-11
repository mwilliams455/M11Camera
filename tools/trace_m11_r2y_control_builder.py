#!/usr/bin/env python3
"""Trace the M11-P R2Y common-control builder feeding R2YMODE.MCCSL.

The closed runtime chain is:
  local control @ fp-0xC4 (0x74 bytes, zeroed)
  -> helper 0x0172C19C(dest, per-pipe template, mode/context)
  -> setter 0x01B1CDA4
  -> R2YMODE.MCCSL bit 4 from control+0x67

This probe disassembles the builder, identifies accesses involving offset 0x67,
reports all direct callers, and inspects the per-pipe template pointer used by
caller 0x0176E75C.  Template inspection uses the project-established Leica data
pointer affine only as supporting evidence; the builder instruction stream is
primary evidence for whether +0x67 is copied/overridden.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
BUILDER = 0x0172C19C
MCCSL_FIELD = 0x67
TEMPLATE_RUNTIME = 0x43377350
TEMPLATE_STRIDE = 0x80
# Previously recovered Leica data-address translation used throughout the M11
# firmware analysis. Kept explicitly labelled as supporting evidence.
DATA_AFFINE = 0x3EFD2A98


def u32(d: bytes, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]


def bl_target(p: int, w: int) -> int | None:
    if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 7) != 5 or ((w >> 24) & 1) == 0:
        return None
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (p + 8 + (imm << 2)) & 0xFFFFFFFF


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


def fmt(i) -> str:
    return f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"


def function_end(d: bytes, e: int, cap: int = 0x3000) -> int:
    for i in disasm(d, e, min(len(d), e + cap)):
        if i.address > e + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
            return i.address + 4
    return min(len(d), e + cap)


def direct_callers(d: bytes, target: int) -> list[int]:
    out = []
    end = len(d) & ~3
    for p in range(0, end, 4):
        if bl_target(p, u32(d, p)) == target:
            out.append(p)
    return out


def mem_accesses(i):
    rows = []
    for op in safe_ops(i):
        if op.type == ARM_OP_MEM:
            base = i.reg_name(op.mem.base) if op.mem.base else ""
            index = i.reg_name(op.mem.index) if op.mem.index else ""
            rows.append((base, index, int(op.mem.disp)))
    return rows


def field_related(i) -> bool:
    return any(disp in (0x65, 0x66, 0x67, 0x68) for _, _, disp in mem_accesses(i))


def arg_register_events(insns):
    """Compactly show r0/r1/r2 moves and memory ops near function entry."""
    out = []
    for i in insns[:180]:
        txt = f"{i.mnemonic} {i.op_str}"
        if any(r in txt for r in ("r0", "r1", "r2")):
            out.append(i)
    return out


def template_rows(d: bytes):
    rows = []
    for pipe in range(3):
        runtime = TEMPLATE_RUNTIME + pipe * TEMPLATE_STRIDE
        raw = runtime - DATA_AFFINE
        if not (0 <= raw and raw + TEMPLATE_STRIDE <= len(d)):
            rows.append((pipe, runtime, raw, None))
            continue
        rec = d[raw:raw + TEMPLATE_STRIDE]
        rows.append((pipe, runtime, raw, rec))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    d = a.unpacked.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    end = function_end(d, BUILDER)
    ins = disasm(d, BUILDER, end)
    callers = direct_callers(d, BUILDER)
    fields = [i for i in ins if field_related(i)]

    lines = [
        "# M11-P R2Y common-control builder trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- builder: `0x{BUILDER:08x}..0x{end:08x}`",
        f"- direct callers: `{[hex(x) for x in callers]}`",
        f"- target MCCSL field: `+0x{MCCSL_FIELD:02x}`",
        "",
        "## Field-related accesses (+0x65..+0x68)",
        "",
    ]
    if fields:
        lines += ["```asm", *[fmt(i) for i in fields], "```"]
    else:
        lines.append("No literal +0x65..+0x68 memory accesses in the builder.")

    lines += ["", "## Argument/dataflow-oriented entry excerpt", "", "```asm"]
    lines += [fmt(i) for i in arg_register_events(ins)]
    lines += ["```", "", "## Whole builder", "", "```asm"]
    lines += [fmt(i) for i in ins]
    lines += ["```", "", "## Per-pipe template bytes (supporting affine evidence)", ""]
    for pipe, runtime, raw, rec in template_rows(d):
        lines += [f"### pipe {pipe}", "", f"- runtime template: `0x{runtime:08x}`", f"- translated raw offset: `0x{raw:08x}`"]
        if rec is None:
            lines.append("- outside canonical image")
            continue
        lo, hi = 0x60, 0x70
        lines += [
            f"- bytes +0x60..+0x6F: `{rec[lo:hi].hex()}`",
            f"- +0x65 YCFBYP candidate byte: `{rec[0x65]}`",
            f"- +0x66 YCFPDD candidate byte: `{rec[0x66]}`",
            f"- +0x67 MCCSL candidate byte: `{rec[0x67]}`",
            f"- +0x68 MCC1BM candidate byte: `{rec[0x68]}`",
        ]

    lines += [
        "",
        "## Decision boundary",
        "",
        "If the builder proves destination +0x67 is copied from the per-pipe template without a mode-dependent override, the template byte can close Leica MCCSL. If the builder synthesizes or overrides the field, trace that source instead. Do not change renderer order from template bytes alone.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
