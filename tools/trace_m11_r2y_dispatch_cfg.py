#!/usr/bin/env python3
"""Trace the Leica M11-P still R2Y dispatcher from its proven call boundary.

This probe starts at the exact still-photo dispatcher entry 0x0176E75C and walks
reachable ARM basic blocks rather than using a first-return heuristic.  It is
intentionally forensic only: it reports calls, indirect calls, argument-object
memory references, MCC-sized constants, and references to the closed
Im_R2Y_Ctrl_Multi_Axis API.  It does not modify renderer policy.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

DISPATCH = 0x0176E75C
MCC_API = 0x01B2D324
CTRL_MULTI_AXIS_SIZE = 0x78C
# Keep traversal in the known R2Y code neighborhood; calls are recorded but not followed.
REGION_LO = 0x01750000
REGION_HI = 0x01790000
MAX_INSNS = 60000


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    # ARM-state BL immediate.
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (off + 8 + (imm << 2)) & 0xFFFFFFFF


def md() -> Cs:
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    c.skipdata = False
    return c


def one(c: Cs, data: bytes, addr: int):
    if addr < 0 or addr + 4 > len(data):
        return None
    xs = list(c.disasm(data[addr:addr + 4], addr, count=1))
    return xs[0] if xs else None


def fmt(i) -> str:
    return f"0x{i.address:08X}: {i.mnemonic} {i.op_str}".rstrip()


def branch_target(i) -> int | None:
    # Capstone ARM immediate branch operands print as '#0x...'.
    m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", i.op_str)
    return int(m.group(1), 0) if m else None


def is_return(i) -> bool:
    m = i.mnemonic.lower()
    s = i.op_str.lower()
    return (m == "bx" and s.strip() == "lr") or (m == "pop" and "pc" in s) or (m.startswith("ldm") and "pc" in s)


def is_uncond_b(i) -> bool:
    return i.mnemonic.lower() == "b"


def is_cond_b(i) -> bool:
    m = i.mnemonic.lower()
    return m.startswith("b") and m not in {"b", "bl", "blx", "bx"}


def walk_cfg(c: Cs, data: bytes):
    q = deque([DISPATCH])
    block_starts = {DISPATCH}
    seen = set()
    insns = {}
    edges = []
    calls = []
    indirect = []
    while q and len(seen) < MAX_INSNS:
        start = q.popleft()
        pc = start
        while REGION_LO <= pc < REGION_HI and pc not in seen and len(seen) < MAX_INSNS:
            i = one(c, data, pc)
            if i is None:
                break
            seen.add(pc)
            insns[pc] = i
            m = i.mnemonic.lower()
            # Record direct BL by raw decoder as a cross-check against Capstone text.
            target = bl_target(pc, u32(data, pc))
            if target is not None:
                calls.append((pc, target))
                pc += 4
                continue
            if m == "blx":
                t = branch_target(i)
                if t is None:
                    indirect.append((pc, i.op_str))
                else:
                    calls.append((pc, t))
                pc += 4
                continue
            if is_return(i):
                break
            if m == "bx":
                indirect.append((pc, i.op_str))
                break
            if is_uncond_b(i):
                t = branch_target(i)
                if t is not None:
                    edges.append((pc, t, "B"))
                    if REGION_LO <= t < REGION_HI and t not in seen:
                        block_starts.add(t); q.append(t)
                break
            if is_cond_b(i):
                t = branch_target(i)
                if t is not None:
                    edges.append((pc, t, i.mnemonic.upper()))
                    if REGION_LO <= t < REGION_HI and t not in seen:
                        block_starts.add(t); q.append(t)
                fall = pc + 4
                edges.append((pc, fall, "fallthrough"))
                if fall not in seen:
                    block_starts.add(fall); q.append(fall)
                break
            pc += 4
    return insns, sorted(block_starts), edges, calls, indirect


def context(insns: dict[int, object], addr: int, radius: int = 10) -> list[str]:
    keys = sorted(insns)
    try:
        n = keys.index(addr)
    except ValueError:
        return []
    lo = max(0, n - radius)
    hi = min(len(keys), n + radius + 1)
    # Do not imply adjacent sorted addresses are one straight-line path; show addresses explicitly.
    return [fmt(insns[k]) for k in keys[lo:hi]]


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
    insns, blocks, edges, calls, indirect = walk_cfg(c, data)
    if not insns or DISPATCH not in insns:
        raise RuntimeError("dispatcher CFG traversal failed")

    direct_mcc_calls = [(at, t) for at, t in calls if t == MCC_API]
    raw_ptr_hits = []
    needle = struct.pack("<I", MCC_API)
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            break
        raw_ptr_hits.append(p); p += 1

    # Search reachable code for immediate constants near the public CtrlMultiAxis size.
    size_hits = []
    for addr, i in sorted(insns.items()):
        vals = [int(x, 0) for x in re.findall(r"#(0x[0-9a-fA-F]+|\d+)", i.op_str)]
        if any(0x760 <= v <= 0x7B0 for v in vals):
            size_hits.append(addr)

    # Direct accesses based on entry argument registers before aliases obscure provenance.
    arg_mem = []
    for addr, i in sorted(insns.items()):
        s = i.op_str.lower()
        if re.search(r"\[(r2|r3)(?:,|\])", s):
            arg_mem.append(addr)

    lines = [
        "# M11-P 2.6.1 still R2Y dispatcher CFG / MCC seam trace",
        "",
        f"- canonical SHA-256: `{digest}`",
        f"- dispatcher: `0x{DISPATCH:08X}`",
        f"- traversal region: `0x{REGION_LO:08X}..0x{REGION_HI:08X}`",
        f"- reachable instructions: `{len(insns)}`",
        f"- discovered basic-block starts: `{len(blocks)}`",
        f"- direct calls: `{len(calls)}`",
        f"- indirect branch/call sites: `{len(indirect)}`",
        "",
        "## Entry",
        "",
        "```asm",
    ]
    for addr in sorted(k for k in insns if DISPATCH <= k < DISPATCH + 0x80):
        lines.append(fmt(insns[addr]))
    lines += ["```", ""]

    lines += ["## Direct calls from reachable dispatcher CFG", ""]
    for at, target in calls:
        lines.append(f"- `0x{at:08X}` -> `0x{target:08X}`")
    lines += ["", "## Indirect calls / branches", ""]
    if indirect:
        for at, op in indirect:
            lines.append(f"- `0x{at:08X}`: `{insns[at].mnemonic} {op}`")
            lines += ["```asm", *context(insns, at, 8), "```", ""]
    else:
        lines.append("- none in reachable CFG")

    lines += ["", "## Closed Multi-Axis API reference checks", ""]
    lines.append(f"- direct BLs to `Im_R2Y_Ctrl_Multi_Axis` (`0x{MCC_API:08X}`): `{len(direct_mcc_calls)}`")
    for at, _ in direct_mcc_calls:
        lines.append(f"  - call at `0x{at:08X}`")
    lines.append(f"- raw little-endian pointers to `0x{MCC_API:08X}` anywhere in firmware: `{len(raw_ptr_hits)}`")
    for off in raw_ptr_hits[:32]:
        lines.append(f"  - file/image offset `0x{off:08X}`")

    lines += ["", "## MCC-object-size immediate candidates", ""]
    lines.append(f"Public `CtrlMultiAxis` size is `0x{CTRL_MULTI_AXIS_SIZE:X}` (1932 bytes).")
    if size_hits:
        for at in size_hits:
            lines += [f"### `0x{at:08X}`", "", "```asm", *context(insns, at, 7), "```", ""]
    else:
        lines.append("- no reachable immediate in the bounded `0x760..0x7B0` range")

    lines += ["", "## Direct entry-argument memory references", ""]
    lines.append("These are only accesses whose printed base is still `r2`/`r3`; aliases are intentionally not inferred here.")
    for at in arg_mem[:200]:
        lines.append(f"- `{fmt(insns[at])}`")

    lines += ["", "## High-value call contexts", ""]
    # Prioritize calls within Milbeaut R2Y hardware/API neighborhoods and calls near the dispatcher entry.
    chosen = []
    for at, target in calls:
        if 0x01B00000 <= target < 0x01B80000 or at < DISPATCH + 0x500:
            chosen.append((at, target))
    for at, target in chosen[:80]:
        lines += [f"### `0x{at:08X}` -> `0x{target:08X}`", "", "```asm", *context(insns, at, 8), "```", ""]

    lines += [
        "## Decision",
        "",
        "This report is a provenance gate, not a renderer change. If the dispatcher exposes an indirect API call/table or a `0x78C` object construction/copy, trace that source next. If it does not, pivot to recovering the neighboring R2Y API function table from the Leica assertion-string identities and then resolve its indirect caller. RENDER1H remains frozen until Leica's actual MCC control object is recovered.",
        "",
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(lines) + "\n")
    print(a.output)


if __name__ == "__main__":
    main()
