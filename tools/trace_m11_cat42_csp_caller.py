#!/usr/bin/env python3
"""Trace the sole Leica caller of the proven Milbeaut CSP register programmer.

Evidence boundary:
- 0x01b68b80 is established by the ordered 11-register CSP footprint probe.
- 0x01731db0 is its sole direct A32 BL callsite in the exact M11-P 2.6.1 image.
- This probe recovers the containing caller, r1 setup context, direct parent calls,
  and Category-42 map offsets. It does not infer hardware pixel arithmetic.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R1

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

CSP_SETTER = 0x01B68B80
CSP_CALLSITE = 0x01731DB0


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(addr: int, word: int) -> int | None:
    # A32 BL immediate: cond | 1011 | imm24. Exclude cond=1111 (BLX encoding).
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm24 = word & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF


def direct_callers(data: bytes, target: int) -> list[int]:
    out = []
    for off in range(0, len(data) - 3, 4):
        if bl_target(off, u32(data, off)) == target:
            out.append(off)
    return out


def one_insn(md: Cs, data: bytes, off: int):
    ins = list(md.disasm(data[off:off + 4], off, count=1))
    return ins[0] if ins else None


def nearest_prologue(md: Cs, data: bytes, target: int, window: int = 0x4000) -> int:
    lo = max(0, target - window) & ~3
    candidates = []
    for off in range(lo, target + 1, 4):
        ins = one_insn(md, data, off)
        if not ins:
            continue
        text = ins.op_str.lower()
        if (ins.mnemonic == "push" and "lr" in text) or (ins.mnemonic.startswith("stm") and "sp!" in text and "lr" in text):
            candidates.append(off)
    if not candidates:
        raise RuntimeError("no A32 function prologue found before CSP callsite")
    return candidates[-1]


def function_instructions(md: Cs, data: bytes, entry: int, callsite: int, max_len: int = 0x5000):
    insns = list(md.disasm(data[entry:min(len(data), entry + max_len)], entry))
    out = []
    passed = False
    for ins in insns:
        out.append(ins)
        if ins.address >= callsite:
            passed = True
        if passed:
            t = (ins.mnemonic + " " + ins.op_str).lower()
            if (ins.mnemonic == "pop" and "pc" in ins.op_str.lower()) or t.startswith("bx lr") or (ins.mnemonic.startswith("ldm") and "pc" in ins.op_str.lower()):
                break
    return out


def fmt_ins(ins) -> str:
    return f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}".rstrip()


def r1_writers(insns, callsite: int):
    out = []
    for ins in insns:
        if ins.address >= callsite:
            break
        try:
            _, writes = ins.regs_access()
        except Exception:
            writes = []
        if ARM_REG_R1 in writes:
            out.append(ins)
    return out


def literal_loads(data: bytes, insns):
    """Decode plain A32 LDR Rt,[PC,+/-imm12] literals in the caller."""
    rows = []
    for ins in insns:
        off = ins.address
        if off + 4 > len(data):
            continue
        w = u32(data, off)
        # single data transfer, immediate offset, pre-indexed, load, base=PC
        if ((w >> 26) & 0x3) != 0x1 or ((w >> 25) & 1) != 0 or ((w >> 24) & 1) != 1 or ((w >> 20) & 1) != 1 or ((w >> 16) & 0xF) != 0xF:
            continue
        imm = w & 0xFFF
        slot = off + 8 + imm if ((w >> 23) & 1) else off + 8 - imm
        if 0 <= slot <= len(data) - 4:
            rows.append((off, (w >> 12) & 0xF, slot, u32(data, slot)))
    return rows


def cat42_maps(data: bytes):
    _, _, _, descs = parse_r2y(data)
    rows = []
    for d in descs:
        if d.get("category") != 42:
            continue
        deps = d.get("dependencies_s32", [])
        state = deps[2] if len(deps) >= 3 else None
        rows.append((state, d.get("map_offset_abs"), d.get("map_size")))
    rows.sort(key=lambda x: (999 if x[0] is None else x[0]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    if bl_target(CSP_CALLSITE, u32(data, CSP_CALLSITE)) != CSP_SETTER:
        raise ValueError("pinned CSP callsite no longer targets pinned CSP setter")

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    entry = nearest_prologue(md, data, CSP_CALLSITE)
    insns = function_instructions(md, data, entry, CSP_CALLSITE)
    parent_calls = direct_callers(data, entry)
    writers = r1_writers(insns, CSP_CALLSITE)
    lits = literal_loads(data, insns)
    maps = cat42_maps(data)

    before = [x for x in insns if x.address < CSP_CALLSITE][-96:]
    after = [x for x in insns if x.address >= CSP_CALLSITE][:32]

    lines = [
        "# M11-P Category-42 CSP caller trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- proven CSP register programmer: `0x{CSP_SETTER:08x}`",
        f"- pinned sole direct CSP callsite: `0x{CSP_CALLSITE:08x}`",
        f"- estimated containing function entry: `0x{entry:08x}`",
        f"- direct A32 BL callers of containing function: `{len(parent_calls)}`",
    ]
    for c in parent_calls[:64]:
        lines.append(f"  - `0x{c:08x}`")

    lines += ["", "## Category-42 recovered map locations", "", "| saturation state | map offset (file) | size |", "|---:|---:|---:|"]
    for state, off, size in maps:
        ss = "?" if state is None else f"{state:+d}"
        oo = "?" if off is None else f"0x{off:08x}"
        lines.append(f"| {ss} | `{oo}` | {size} |")

    lines += ["", "## Writes to r1 before the CSP call", ""]
    for ins in writers[-48:]:
        lines.append(f"- `{fmt_ins(ins)}`")
    if writers:
        lines += ["", f"Nearest r1 writer before call: `{fmt_ins(writers[-1])}`"]

    lines += ["", "## A32 PC-relative literal loads in containing function", "", "| instruction | Rt | literal slot | value | matches Category-42 file offset |", "|---:|---:|---:|---:|:---:|"]
    map_offsets = {off for _, off, _ in maps if off is not None}
    for addr, rt, slot, value in lits[:256]:
        match = "yes" if value in map_offsets else ""
        lines.append(f"| `0x{addr:08x}` | r{rt} | `0x{slot:08x}` | `0x{value:08x}` | {match} |")

    lines += ["", "## Immediate context before/through CSP call", "", "```asm"]
    lines += [fmt_ins(x) for x in before + after]
    lines += ["```", "", "## Interpretation boundary", "", "This trace is primary firmware evidence for the software call path only. If the caller passes an already-selected 44-byte Category-42 record directly as r1, that closes Leica parameter-transfer semantics. It does not by itself establish CSYKY endpoint direction, chroma magnitude, CSYGA fractional precision, or the internal CSP pixel equation.", ""]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines))
    print(args.output)


if __name__ == "__main__":
    main()
