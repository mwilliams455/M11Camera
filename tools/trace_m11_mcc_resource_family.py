#!/usr/bin/env python3
"""Trace the Leica M11-P Cat27..40 family against Milbeaut multi-axis MCC.

Known wrapper family at 0x0172EC18 requests categories:
27, 28, 30, 32, 34, 36, 38, 40.

This report correlates those R2YS payload sizes/dependencies with the wrapper's
actual call sequence and low-level 0x01Bxxxxx consumers.  It does not infer
photographic arithmetic from category numbering alone.

Re-run after primary-firmware closure of Im_R2Y_Ctrl_Multi_Axis at 0x01B2D324
and the complete F_R2Y.MCC hardware footprint, so any low-level overlap can now
be judged against a concrete MCC target rather than category naming.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

from extract_m11p_forensics import parse_r2y, map_bytes, sha

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
WRAPPER = 0x0172EC18
LOOKUP = 0x0178D0A8
CATS = (27, 28, 30, 32, 34, 36, 38, 40)


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
    return list(md().disasm(d[lo:hi], lo))


def function_end(d: bytes, entry: int, cap: int = 0x5000) -> int:
    for i in disasm(d, entry, min(len(d), entry + cap)):
        if i.address > entry + 8 and ((i.mnemonic == "pop" and "pc" in i.op_str) or (i.mnemonic == "bx" and i.op_str.strip() == "lr")):
            return i.address + 4
    return min(len(d), entry + cap)


def rname(i, op) -> str | None:
    return i.reg_name(op.reg) if op.type == ARM_OP_REG else None


def imm(i, op) -> int | None:
    return int(op.imm) if op.type == ARM_OP_IMM else None


def recover_reg_imm(insns, before_idx: int, reg: str, window: int = 18) -> int | None:
    lo = max(0, before_idx - window)
    val = None
    for j in range(lo, before_idx):
        i = insns[j]
        if len(i.operands) < 2 or rname(i, i.operands[0]) != reg:
            continue
        x = imm(i, i.operands[1])
        if x is None:
            continue
        if i.mnemonic in ("mov", "movw"):
            val = x & 0xFFFF
        elif i.mnemonic == "movt" and val is not None:
            val |= (x & 0xFFFF) << 16
    return val


def recover_request_category(insns, lookup_idx: int) -> int | None:
    # Resolver gets r0 = fp - BASE. Category is request+0x08.
    base = None
    for j in range(lookup_idx - 1, max(-1, lookup_idx - 48), -1):
        i = insns[j]
        if len(i.operands) < 3:
            continue
        if rname(i, i.operands[0]) != "r0" or rname(i, i.operands[1]) not in ("fp", "r11"):
            continue
        x = imm(i, i.operands[2])
        if x is None:
            continue
        if i.mnemonic == "sub":
            base = x
            break
    if base is None:
        return None
    want_disp = -(base - 8)
    for j in range(lookup_idx - 1, max(-1, lookup_idx - 80), -1):
        i = insns[j]
        if not i.mnemonic.startswith("str") or len(i.operands) < 2:
            continue
        mem = i.operands[1]
        if mem.type != ARM_OP_MEM:
            continue
        b = i.reg_name(mem.mem.base) if mem.mem.base else ""
        if b not in ("fp", "r11") or int(mem.mem.disp) != want_disp:
            continue
        src = rname(i, i.operands[0])
        if src:
            v = recover_reg_imm(insns, j, src, 24)
            if v is not None and 0 <= v < 256:
                return v
    return None


def payload_summary(raw: bytes) -> dict:
    out = {"size": len(raw), "sha": sha(raw), "head_hex": raw[:32].hex(), "tail_hex": raw[-32:].hex() if raw else ""}
    if len(raw) % 2 == 0:
        vals = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        out["i16_count"] = len(vals)
        out["i16_head"] = list(vals[:18])
        out["i16_tail"] = list(vals[-18:])
        out["i16_min"] = min(vals) if vals else None
        out["i16_max"] = max(vals) if vals else None
        out["i16_zero_pct"] = round((sum(v == 0 for v in vals) / len(vals) * 100.0), 3) if vals else None
    return out


def setter_footprint(d: bytes, entry: int, cap: int = 0x1800):
    end = function_end(d, entry, cap)
    ins = disasm(d, entry, end)
    imms = []
    for i in ins:
        for op in i.operands:
            if op.type == ARM_OP_MEM and op.mem.disp >= 0:
                imms.append(int(op.mem.disp))
    return end, sorted(set(imms))[:160]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    d = a.unpacked.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    base, _, _, descs = parse_r2y(d)
    by_cat = {c: [x for x in descs if int(x["category"]) == c] for c in CATS}

    end = function_end(d, WRAPPER)
    ins = disasm(d, WRAPPER, end)
    events = []
    active_cat = None
    for n, i in enumerate(ins):
        t = bl_target(i.address, u32(d, i.address))
        if t is None:
            continue
        if t == LOOKUP:
            active_cat = recover_request_category(ins, n)
            events.append((i.address, "lookup", active_cat, t))
        else:
            kind = "low_r2y" if 0x01B00000 <= t < 0x01C00000 else "call"
            events.append((i.address, kind, active_cat, t))

    low_targets = sorted({t for _, k, _, t in events if k == "low_r2y"})

    lines = [
        "# M11-P Cat27..40 / MCC resource-family trace",
        "",
        f"- unpacked SHA-256: `{digest}`",
        f"- wrapper: `0x{WRAPPER:08x}..0x{end:08x}`",
        f"- resolver: `0x{LOOKUP:08x}`",
        f"- target categories: `{list(CATS)}`",
        "",
        "## R2YS payload inventory",
        "",
    ]
    for c in CATS:
        rows = by_cat[c]
        lines += [f"### Category {c}", "", f"descriptors: `{len(rows)}`", ""]
        for r in rows:
            raw = map_bytes(d, base, r)
            s = payload_summary(raw)
            lines += [
                f"- index `{r['index']}` flags `{r['flags_hex']}` deps `{r['dependencies_s32']}`",
                f"- size `{s['size']}` SHA `{s['sha']}`",
                f"- i16 count `{s.get('i16_count')}` min/max `{s.get('i16_min')}/{s.get('i16_max')}` zero `{s.get('i16_zero_pct')}%`",
                f"- i16 head `{s.get('i16_head')}`",
                f"- i16 tail `{s.get('i16_tail')}`",
                "",
            ]

    lines += ["## Wrapper call sequence", "", "| callsite | kind | active category | target |", "| --- | --- | ---: | --- |"]
    for p, k, c, t in events:
        lines.append(f"| `0x{p:08x}` | {k} | {c if c is not None else '-'} | `0x{t:08x}` |")

    lines += ["", "## Low-level R2Y setter footprints", ""]
    for t in low_targets:
        se, offs = setter_footprint(d, t)
        lines += [f"### `0x{t:08x}..0x{se:08x}`", "", f"memory displacements: `{[hex(x) for x in offs]}`", ""]

    lines += ["## Wrapper disassembly", "", "```asm"]
    lines += [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in ins]
    lines += ["```", "", "## Interpretation boundary", "", "Category-to-MCC identity becomes closed only when payload shape and concrete low-level F_R2Y.MCC register consumers agree. No renderer change is justified by category adjacency alone.", ""]

    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
