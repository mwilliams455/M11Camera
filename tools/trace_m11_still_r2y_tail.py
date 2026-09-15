#!/usr/bin/env python3
"""Focused trace of the late still-R2Y setup block around 0x017BA8xx.

The broad first-pass buffer tracer used a first-return function heuristic, which
is unsuitable for this branch-heavy job. This probe deliberately disassembles a
fixed, verified code window and reports every direct call plus local r0-r3 setup.
It is a discovery probe only; no renderer behavior changes.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

WINDOW_LO = 0x017BA600
WINDOW_HI = 0x017BAA80
FOCUS_CALLS = {0x017BA8A4, 0x017BA8B4, 0x017BA8C0}
TRACK = ("r0", "r1", "r2", "r3")
DEFS = {"mov", "movs", "movw", "movt", "mvn", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "add", "sub", "rsb", "orr", "eor", "and", "bic", "lsl", "lsr", "asr", "adr", "ubfx", "sbfx", "uxtb", "uxth", "sxtb", "sxth"}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (off + 8 + (imm << 2)) & 0xFFFFFFFF


def md() -> Cs:
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    c.skipdata = True
    return c


def fmt(i) -> str:
    return f"0x{i.address:08X}: {i.mnemonic} {i.op_str}".rstrip()


def dst(i) -> str | None:
    if i.mnemonic.lower() not in DEFS or not i.op_str:
        return None
    d = i.op_str.split(",", 1)[0].strip().lower()
    return d if d in TRACK else None


def last_defs(insns, idx: int, lookback: int = 48) -> dict[str, str]:
    out = {r: "<not found>" for r in TRACK}
    for i in reversed(insns[max(0, idx - lookback):idx]):
        d = dst(i)
        if d in out and out[d] == "<not found>":
            out[d] = fmt(i)
        if all(v != "<not found>" for v in out.values()):
            break
    return out


def nearest_prologue(c: Cs, data: bytes, target: int, window: int = 0x5000) -> int | None:
    best = None
    lo = max(0, target - window) & ~3
    for off in range(lo, target + 1, 4):
        one = list(c.disasm(data[off:off + 4], off, count=1))
        if not one:
            continue
        i = one[0]
        s = i.op_str.lower()
        if (i.mnemonic == "push" and "lr" in s) or (i.mnemonic.startswith("stm") and "sp!" in s and "lr" in s):
            best = off
    return best


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
    insns = list(c.disasm(data[WINDOW_LO:WINDOW_HI], WINDOW_LO))
    by_addr = {i.address: n for n, i in enumerate(insns)}

    calls = []
    for n, i in enumerate(insns):
        if i.address + 4 > len(data):
            continue
        t = bl_target(i.address, u32(data, i.address))
        if t is not None:
            calls.append((n, i.address, t))

    lines = [
        "# M11-P focused still-R2Y late-block trace",
        "",
        f"- canonical SHA-256: `{digest}`",
        f"- fixed window: `0x{WINDOW_LO:08X}..0x{WINDOW_HI:08X}`",
        f"- direct BL calls in window: `{len(calls)}`",
        "",
        "## Focus call verification",
        "",
    ]
    for at in sorted(FOCUS_CALLS):
        n = by_addr.get(at)
        if n is None:
            lines.append(f"- `0x{at:08X}`: no decoded instruction")
            continue
        i = insns[n]
        t = bl_target(at, u32(data, at))
        lines.append(f"- `0x{at:08X}`: `{fmt(i)}` -> `{hex(t) if t is not None else 'not-BL'}`")
    lines += ["", "## All calls with local argument setup", ""]

    for n, at, target in calls:
        defs = last_defs(insns, n)
        lines += [f"### `0x{at:08X}` -> `0x{target:08X}`", ""]
        for r in TRACK:
            lines.append(f"- `{r}`: `{defs[r]}`")
        if at in FOCUS_CALLS or 0x017BA800 <= at <= 0x017BA980:
            lines += ["", "```asm"]
            lo = max(0, n - 34)
            hi = min(len(insns), n + 12)
            lines += [fmt(x) for x in insns[lo:hi]]
            lines += ["```"]
        lines.append("")

    lines += ["## Focus callee entry/prologue locators", ""]
    focus_targets = []
    for at in sorted(FOCUS_CALLS):
        if at in by_addr:
            t = bl_target(at, u32(data, at))
            if t is not None:
                focus_targets.append(t)
    for target in sorted(set(focus_targets)):
        pro = nearest_prologue(c, data, target)
        lines.append(f"- target `0x{target:08X}` nearest prior prologue: `{hex(pro) if pro is not None else 'none'}`")
        lo = max(0, target - 0x40)
        hi = min(len(data), target + 0x120)
        lines += ["", "```asm"]
        lines += [fmt(i) for i in c.disasm(data[lo:hi], lo)]
        lines += ["```", ""]

    lines += [
        "## Decision rule",
        "",
        "Use the exact late-block call/argument chain to identify output-buffer programming. Do not promote a JPEG/output closure from guessed function boundaries. If these calls resolve to R2Y YYW address/format setters, trace their source fields and then follow the same buffers into the next scheduled consumer.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
