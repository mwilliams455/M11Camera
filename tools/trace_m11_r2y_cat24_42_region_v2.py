#!/usr/bin/env python3
"""M11-P R2Y Cat24..Cat42 wrapper-region trace, v2.

Corrects the v1 category-recovery mistake: Leica does not pass the category as
an immediate in r1.  It constructs the selector request on the stack and writes
category at request+0x08 before calling 0x0178D0A8.

The report:
  * recovers selector categories from request+0x08;
  * emits every wrapper in 0x0172D000..0x01733000 that calls the R2YS resolver
    or a low-level 0x01Bxxxxx R2Y routine, including the previously omitted
    0x0172E5EC bridge wrapper;
  * correlates recovered category IDs with R2YS descriptor/map sizes and
    dependency metadata;
  * dumps focused disassembly for the bridge and Cat41/Cat42 wrappers and their
    low-level setters.

Configuration/programming order is not promoted to silicon pixel-stage order.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_FP

from extract_m11p_forensics import parse_r2y, map_bytes, sha as sha256

EXPECTED = "28528c24555f93ff69b6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
LOOKUP = 0x0178D0A8
LO = 0x0172D000
HI = 0x01733000
KNOWN_YCC = 0x0172DFC0
BRIDGE = 0x0172E5EC
CAT41 = 0x01731490
KNOWN_CSP = 0x01731970
FOCUS_SETTERS = (0x01B624AC, 0x01B62BA4, 0x01B68130, 0x01B68B80)


def u32(d: bytes, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]


def is_push_lr(w: int) -> bool:
    return (w & 0xFFFF4000) == 0xE92D4000


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


def disasm(d: bytes, s: int, e: int):
    return list(md().disasm(d[s:e], s))


def extent(d: bytes, e: int, hi: int = HI, maxlen: int = 0x4000) -> int:
    for i in disasm(d, e, min(len(d), e + maxlen, hi)):
        if i.address > e + 8 and (
            (i.mnemonic == "pop" and "pc" in i.op_str)
            or (i.mnemonic == "bx" and i.op_str.strip() == "lr")
        ):
            return i.address + 4
    return min(len(d), e + maxlen, hi)


def regname(i, op) -> str | None:
    if op.type != ARM_OP_REG:
        return None
    return i.reg_name(op.reg)


def imm_of(i, op) -> int | None:
    if op.type != ARM_OP_IMM:
        return None
    return int(op.imm)


def recover_request_base(insns, lookup_idx: int) -> tuple[str, int] | None:
    """Recover r0 = fp - BASE (or add r0,fp,#negative) before resolver call."""
    for j in range(lookup_idx - 1, max(-1, lookup_idx - 48), -1):
        i = insns[j]
        if len(i.operands) < 3:
            continue
        if regname(i, i.operands[0]) != "r0" or regname(i, i.operands[1]) not in ("fp", "r11"):
            continue
        v = imm_of(i, i.operands[2])
        if v is None:
            continue
        if i.mnemonic == "sub":
            return ("fp", v)
        if i.mnemonic == "add" and v < 0:
            return ("fp", -v)
    return None


def store_fp_offset(i) -> int | None:
    if not i.mnemonic.startswith("str") or len(i.operands) < 2:
        return None
    mem = i.operands[1]
    if mem.type != ARM_OP_MEM:
        return None
    base = i.reg_name(mem.mem.base) if mem.mem.base else ""
    if base not in ("fp", "r11"):
        return None
    return int(mem.mem.disp)


def recover_reg_imm(insns, before_idx: int, reg: str, window: int = 18) -> int | None:
    lo = max(0, before_idx - window)
    val = None
    for j in range(lo, before_idx):
        i = insns[j]
        if len(i.operands) < 2 or regname(i, i.operands[0]) != reg:
            continue
        x = imm_of(i, i.operands[1])
        if x is None:
            continue
        if i.mnemonic in ("mov", "movw"):
            val = x & 0xFFFF
        elif i.mnemonic == "movt" and val is not None:
            val |= (x & 0xFFFF) << 16
    return val


def recover_category(insns, lookup_idx: int) -> tuple[int | None, str]:
    rb = recover_request_base(insns, lookup_idx)
    if rb is None:
        return None, "request base not recovered"
    _, base = rb
    want = -(base - 8)
    for j in range(lookup_idx - 1, max(-1, lookup_idx - 80), -1):
        i = insns[j]
        if store_fp_offset(i) != want or not i.operands:
            continue
        src = regname(i, i.operands[0])
        if src is None:
            continue
        v = recover_reg_imm(insns, j, src, 20)
        if v is not None and 0 <= v <= 0xFF:
            return v, f"request=fp-0x{base:x}; category slot fp{want:+#x}; source {src}"
    return None, f"request=fp-0x{base:x}; category slot fp{want:+#x}; store not resolved"


def descriptor_summary(d: bytes) -> dict[int, list[dict]]:
    base, _, _, descs = parse_r2y(d)
    out: dict[int, list[dict]] = {}
    for x in descs:
        raw = map_bytes(d, base, x)
        out.setdefault(int(x["category"]), []).append({
            "index": x["index"],
            "flags": x["flags_hex"],
            "size": len(raw),
            "deps": x["dependencies_s32"],
            "sha": sha256(raw),
        })
    return out


def setter_extent(d: bytes, e: int, maxlen: int = 0x1200) -> int:
    for i in disasm(d, e, min(len(d), e + maxlen)):
        if i.address > e + 8 and (
            (i.mnemonic == "pop" and "pc" in i.op_str)
            or (i.mnemonic == "bx" and i.op_str.strip() == "lr")
        ):
            return i.address + 4
    return min(len(d), e + maxlen)


def fmt(i) -> str:
    return f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    d = a.unpacked.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    if digest != EXPECTED:
        raise ValueError(f"unexpected M11-P unpacked SHA-256 {digest}")

    desc = descriptor_summary(d)
    region = disasm(d, LO, HI)
    entries = sorted({i.address for i in region if is_push_lr(u32(d, i.address))})
    funcs = []
    for e in entries:
        en = extent(d, e)
        if en <= e:
            continue
        ins = disasm(d, e, en)
        calls = []
        lookups = []
        for n, i in enumerate(ins):
            t = bl_target(i.address, u32(d, i.address))
            if t is None:
                continue
            calls.append((i.address, t))
            if t == LOOKUP:
                cat, why = recover_category(ins, n)
                lookups.append((i.address, cat, why))
        low = [(cs, t) for cs, t in calls if 0x01B00000 <= t < 0x01C00000]
        if lookups or low:
            funcs.append((e, en, ins, lookups, low))

    lines = [
        "# M11-P R2Y Cat24..Cat42 wrapper-region trace v2",
        "",
        f"- SHA-256: `{digest}`",
        f"- scan: `0x{LO:08x}..0x{HI:08x}`",
        f"- resolver: `0x{LOOKUP:08x}`",
        "- category ABI: selector request field `request+0x08` (corrected from v1)",
        "",
        "## Compact map",
        "",
        "| Wrapper | Categories | Low-level R2Y calls |",
        "| --- | --- | --- |",
    ]
    for e, en, ins, lookups, low in funcs:
        cats = [x[1] for x in lookups if x[1] is not None]
        lowtxt = ", ".join(f"0x{t:08x}" for _, t in low) or "-"
        lines.append(f"| `0x{e:08x}..0x{en:08x}` | `{cats}` | {lowtxt} |")

    cats_seen = sorted({x[1] for _, _, _, lookups, _ in funcs for x in lookups if x[1] is not None})
    lines += ["", "## R2YS descriptor correlation", "", "| Cat | descriptors | map sizes | flags | dependencies |", "| ---: | ---: | --- | --- | --- |"]
    for cat in cats_seen:
        rows = desc.get(cat, [])
        sizes = [r["size"] for r in rows]
        flags = sorted({r["flags"] for r in rows})
        deps = [r["deps"] for r in rows[:8]]
        lines.append(f"| {cat} | {len(rows)} | `{sizes}` | `{flags}` | `{deps}` |")

    focus_entries = {KNOWN_YCC, BRIDGE, CAT41, KNOWN_CSP}
    lines += ["", "## Focused wrappers", ""]
    for e, en, ins, lookups, low in funcs:
        if e not in focus_entries:
            continue
        lines += [
            f"### Wrapper `0x{e:08x}..0x{en:08x}`",
            "",
            f"- recovered lookups: `{[(hex(cs), cat, why) for cs, cat, why in lookups]}`",
            f"- low-level calls: `{[(hex(cs), hex(t)) for cs, t in low]}`",
            "",
            "```asm",
        ]
        lines += [fmt(i) for i in ins]
        lines += ["```", ""]

    lines += ["## Focused low-level setters", ""]
    for s in FOCUS_SETTERS:
        en = setter_extent(d, s)
        ins = disasm(d, s, en)
        lines += [f"### Setter `0x{s:08x}..0x{en:08x}`", "", "```asm"]
        lines += [fmt(i) for i in ins]
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "This report closes the Leica selector/category association for the wrapper region and exposes the concrete low-level R2Y consumers. Category/configuration order and register-address order remain supporting evidence only until matched to public R2Y block semantics/dataflow.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
