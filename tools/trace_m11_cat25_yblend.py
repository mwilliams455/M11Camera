#!/usr/bin/env python3
"""Trace M11-P R2YS Category 25 into the live YC/YBLEND control.

Discovery pass: enumerate exact Cat25 maps, show the Cat24/25 YC wrapper around
selector 0x19, and expose the live YC hardware setter's input-field loads and
YBLEND register packing. No renderer change is made by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_R1

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y, map_bytes, sha

YC_WRAPPER = 0x0172DFC0
YC_CALLSITE = 0x0172E238
YC_SETTER = 0x01B624AC
CAT25 = 25


def md() -> Cs:
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    c.skipdata = True
    return c


def fmt(i) -> str:
    return f"0x{i.address:08X}: {i.mnemonic} {i.op_str}".rstrip()


def cat_maps(data: bytes, category: int):
    base, _, _, descs = parse_r2y(data)
    out = []
    for d in descs:
        if d["category"] == category:
            raw = map_bytes(data, base, d)
            out.append((d, raw))
    return out


def memory_operands(i):
    rows = []
    try:
        ops = i.operands
    except Exception:
        return rows
    for op in ops:
        if op.type == ARM_OP_MEM:
            rows.append((i.reg_name(op.mem.base) if op.mem.base else "", int(op.mem.disp)))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    c = md()

    maps = cat_maps(data, CAT25)
    wrapper = list(c.disasm(data[YC_WRAPPER:YC_CALLSITE + 0x20], YC_WRAPPER))
    setter = list(c.disasm(data[YC_SETTER:YC_SETTER + 0x700], YC_SETTER))

    # Locate selector/category immediate 0x19 in the live wrapper.
    selector_hits = [i for i in wrapper if "#0x19" in i.op_str.lower() or i.op_str.strip().endswith("#25")]

    # Focus setter accesses whose memory base is r1, the known control pointer.
    r1_loads = []
    for i in setter:
        mem = memory_operands(i)
        if any(base == "r1" for base, _ in mem):
            r1_loads.append(i)

    # Register footprint guard inherited from the Cat24 closure.
    setter_text = "\n".join(fmt(i) for i in setter)
    footprint = ["#0x100", "#0x104", "#0x108", "#0x10c", "#0x110", "#0x120"]
    missing = [x for x in footprint if x not in setter_text.lower()]
    if missing:
        raise RuntimeError(f"YC setter footprint drifted: {missing}")

    lines = [
        "# M11-P Category25 / YBLEND discovery trace",
        "",
        f"- canonical unpacked SHA-256: `{digest}`",
        f"- YC wrapper: `0x{YC_WRAPPER:08X}`",
        f"- YC setter callsite: `0x{YC_CALLSITE:08X}`",
        f"- YC hardware setter: `0x{YC_SETTER:08X}`",
        f"- Category25 descriptor count: `{len(maps)}`",
        f"- selector-0x19 hits in wrapper: `{len(selector_hits)}`",
        "",
        "## Category25 maps",
        "",
    ]
    if not maps:
        lines.append("No Category25 maps found.")
    for n, (d, raw) in enumerate(maps):
        lines += [
            f"### map {n}",
            f"- descriptor index: `{d['index']}`",
            f"- flags: `{d['flags_hex']}`",
            f"- dependencies: `{d['dependencies_s32']}`",
            f"- size: `{len(raw)}`",
            f"- absolute offset: `0x{d['map_offset_abs']:08X}`",
            f"- SHA-256: `{sha(raw)}`",
            f"- raw hex: `{raw.hex()}`",
        ]
        if len(raw) % 2 == 0:
            n16 = len(raw) // 2
            lines.append(f"- uint16 LE: `{list(struct.unpack('<' + 'H' * n16, raw))}`")
            lines.append(f"- int16 LE: `{list(struct.unpack('<' + 'h' * n16, raw))}`")
        lines.append(f"- uint8: `{list(raw)}`")
        lines.append("")

    lines += ["## Selector 0x19 contexts in live YC wrapper", ""]
    for hit in selector_hits:
        lines += [f"### hit `0x{hit.address:08X}`", "", "```asm"]
        lo = max(YC_WRAPPER, hit.address - 0x80)
        hi = min(YC_CALLSITE + 0x20, hit.address + 0x140)
        lines += [fmt(i) for i in wrapper if lo <= i.address <= hi]
        lines += ["```", ""]

    lines += [
        "## YC wrapper tail into hardware setter",
        "",
        "```asm",
    ]
    lines += [fmt(i) for i in wrapper if YC_CALLSITE - 0x180 <= i.address <= YC_CALLSITE + 0x10]
    lines += ["```", ""]

    lines += [
        "## YC setter r1/control-pointer memory accesses",
        "",
        "The public Milbeaut ABI defines nine signed YC coefficients followed by Y/Yb blend ratios; these loads show Leica's actual compiled field offsets before the YBLEND write.",
        "",
        "```asm",
    ]
    lines += [fmt(i) for i in r1_loads]
    lines += ["```", ""]

    lines += ["## YC setter YBLEND-area context", "", "```asm"]
    for i in setter:
        if "#0x120" in i.op_str.lower():
            lo = i.address - 0x80
            hi = i.address + 0x100
            lines += [fmt(x) for x in setter if lo <= x.address <= hi]
    lines += ["```", ""]

    lines += [
        "## Decision boundary",
        "",
        "Promote Category25 only if the exact Cat25 payload is shown to populate the same local control fields that the pinned YC setter writes into YBLEND.YYBLND/YBBLND. If those ratios are nonzero, their pixel arithmetic still requires hardware/public-document evidence before changing RENDER1H/RENDER1I; do not infer the blend formula photographically.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
