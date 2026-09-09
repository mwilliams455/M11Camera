#!/usr/bin/env python3
"""Trace leaf/trampoline object helpers used by the Leica M11 gamma serializer.

The first helper inventory used next-prologue boundaries and therefore truncated
several leaf functions that have no stack-frame prologue. This pass deliberately
disassembles bounded windows around the helper entrypoints and follows an entry
unconditional branch when present. It emits derived A32 control-flow metadata
only; helper names remain descriptive/provisional.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
TARGETS = {
    "object_helper_e6ec": 0x0169E6EC,
    "object_helper_e748": 0x0169E748,
    "object_helper_e7a4": 0x0169E7A4,
    "object_helper_e954": 0x0169E954,
    "object_helper_d87c": 0x0169D87C,
    "selector_alias_d980": 0x0169D980,
    "object_helper_e0e8": 0x0169E0E8,
    "object_helper_e1d4": 0x0169E1D4,
    "object_helper_e15c": 0x0169E15C,
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def branch_target(off: int, word: int) -> tuple[str,int] | None:
    # A32 B/BL, condition preserved only in mnemonic from Capstone.
    if ((word >> 25) & 0x7) != 0x5:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    target = off + 8 + (imm << 2)
    link = bool(word & 0x01000000)
    return ("bl" if link else "b", target)


def window(data: bytes, start: int, size: int = 0x140) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    rows = []
    end = min(len(data), start + size)
    for ins in md.disasm(data[start:end], start):
        note = ""
        if ins.address + 4 <= len(data) and not (ins.address & 3):
            bt = branch_target(ins.address, u32(data, ins.address))
            if bt is not None:
                note = f" ; {bt[0].upper()}=0x{bt[1]:08x}"
        rows.append(f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}{note}".rstrip())
    return rows


def entry_branch(data: bytes, start: int) -> int | None:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    ins = next(md.disasm(data[start:start+4], start), None)
    if ins is None or ins.mnemonic != "b":
        return None
    bt = branch_target(start, u32(data,start))
    return bt[1] if bt else None


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P SHA-256 {digest}")
    lines = [
        "# M11-P R2A object leaf/trampoline helper trace", "",
        f"- SHA-256: `{digest}`",
        "- fixed windows are used because these helpers may be leaf functions without prologues.",
        "- an entry unconditional branch is followed into a second bounded window.", "",
    ]
    for label,start in TARGETS.items():
        follow = entry_branch(data,start)
        lines += [f"## `{label}` `0x{start:08x}`", ""]
        if follow is not None:
            lines.append(f"- entry unconditional branch target: `0x{follow:08x}`")
        else:
            lines.append("- entry unconditional branch target: none")
        lines += ["", "### Entry window", "", "```text"]
        lines.extend(window(data,start,0x140))
        lines += ["```", ""]
        if follow is not None and 0 <= follow < len(data):
            lines += ["### Followed branch-target window", "", "```text"]
            lines.extend(window(data,follow,0x180))
            lines += ["```", ""]
    lines += [
        "## Interpretation boundary", "",
        "A bounded leaf window is not by itself a recovered function extent. Semantics are promoted only when the entry/followed control flow agrees with repeated caller usage and serializer branching.", ""
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
