#!/usr/bin/env python3
"""Trace the Leica M11-P BB06 submit transport beyond 0x015765b4.

Leica-primary evidence established that 0x015765b4 forwards a packet pointer and
length to 0x0194a5a4 with r0=0x31 when the transport gate is enabled. This pass
maps the target body, all direct A32 callers, immediate command IDs passed in r0,
and the target's direct callees. Names remain provisional.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
TARGET = 0x0194A5A4
KNOWN_WRAPPER = 0x015765B4
SCAN_START = 0x01000000
SCAN_END = 0x02000000


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    if (word & 0x0F000000) != 0x0B000000:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def is_prologue(ins) -> bool:
    return ins is not None and ins.mnemonic in ("push", "stmdb") and "lr" in ins.op_str and (ins.mnemonic == "push" or "sp" in ins.op_str)


def nearest_prologue(data: bytes, center: int, radius: int = 0x1200) -> int | None:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    best = None
    for off in range(max(SCAN_START, center-radius) & ~3, center+1, 4):
        ins = next(md.disasm(data[off:off+4], off), None)
        if is_prologue(ins):
            best = off
    return best


def next_prologue(data: bytes, start: int, max_len: int = 0x1800) -> int:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    for off in range(start+4, min(len(data)-4, start+max_len), 4):
        ins = next(md.disasm(data[off:off+4], off), None)
        if is_prologue(ins):
            return off
    return min(len(data), start+max_len)


def all_callers(data: bytes, target: int) -> list[int]:
    out = []
    end = min(SCAN_END, len(data)-4) & ~3
    for off in range(SCAN_START & ~3, end, 4):
        if bl_target(off, u32(data, off)) == target:
            out.append(off)
    return out


def disasm(data: bytes, start: int, end: int, max_ins: int | None = None) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    rows = []
    for i, ins in enumerate(md.disasm(data[max(0,start):min(len(data),end)], max(0,start))):
        if max_ins is not None and i >= max_ins:
            break
        note = ""
        if ins.address + 4 <= len(data) and not (ins.address & 3):
            bt = bl_target(ins.address, u32(data, ins.address))
            if bt is not None:
                note = f" ; BL=0x{bt:08x}"
        rows.append(f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}{note}".rstrip())
    return rows


def recent_r0_immediate(data: bytes, call: int, lookback: int = 0x60) -> tuple[int,int,str] | None:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    last = None
    for ins in md.disasm(data[max(SCAN_START,call-lookback):call], max(SCAN_START,call-lookback)):
        if not ins.mnemonic.startswith("mov"):
            continue
        m = re.fullmatch(r"r0, #(0x[0-9a-f]+|[0-9]+)", ins.op_str)
        if m:
            last = (ins.address, int(m.group(1),0), ins.mnemonic)
    return last


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P SHA-256 {digest}")
    callers = all_callers(data, TARGET)
    start = nearest_prologue(data, TARGET) or TARGET
    end = next_prologue(data, start)
    callees = Counter()
    for off in range(start, end, 4):
        bt = bl_target(off, u32(data, off))
        if bt is not None:
            callees[bt] += 1
    commands = Counter()
    caller_rows = []
    for c in callers:
        pro = nearest_prologue(data, c)
        imm = recent_r0_immediate(data, c)
        if imm is not None:
            commands[imm[1]] += 1
        caller_rows.append((c, pro, imm))

    lines = [
        "# M11-P R2A BB06 submit transport trace",
        "",
        f"- SHA-256: `{digest}`",
        f"- target: `0x{TARGET:08x}`",
        f"- known BB06 wrapper: `0x{KNOWN_WRAPPER:08x}`",
        f"- target body bound: `0x{start:08x}–0x{end:08x}` (`0x{end-start:x}` bytes)",
        f"- direct A32 callers: `{len(callers)}`",
        f"- direct target-body callees: `{len(callees)}`",
        "",
        "## Observed immediate command IDs in r0 at target callsites",
        "",
    ]
    if commands:
        for cmd, n in sorted(commands.items()):
            lines.append(f"- `0x{cmd:x}`: `{n}` callsite(s)")
    else:
        lines.append("- none recovered by local-immediate scan")
    lines += ["", "## Target direct callees", ""]
    for t,n in callees.most_common(40):
        lines.append(f"- `0x{t:08x}`: `{n}` call(s)")
    lines += ["", "## Target body", "", "```text"]
    lines.extend(disasm(data, start, end, 260))
    lines += ["```", "", "## Caller windows", ""]
    for c,pro,imm in caller_rows:
        lines.append(f"### call `0x{c:08x}` / prologue `{('0x%08x'%pro) if pro else 'unknown'}`")
        if imm:
            lines.append(f"- nearest obvious r0 immediate: `0x{imm[1]:x}` at `0x{imm[0]:08x}` ({imm[2]})")
        lines.append("```text")
        lines.extend(disasm(data, max(SCAN_START,c-0x60), c+0x10, 36))
        lines += ["```", ""]
    lines += [
        "## Interpretation boundary", "",
        "A recovered r0 immediate is a local caller observation only. Transport semantics require convergence between command-ID families, target-body behavior and downstream callee structure; no IPC/mailbox name is assigned from the numeric 0x31 alone.", ""
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(report(a.unpacked.read_bytes()))
    print(a.output)


if __name__ == "__main__":
    main()
