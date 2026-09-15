#!/usr/bin/env python3
"""Decode the still R2Y dispatcher's 17-way mode jump table.

The common dispatcher path ends in:
  cmp   r3, #0x10
  ldrls pc, [pc, r3, lsl #2]
  b     default
at 0x0176FF94..0x0176FF9C. ARM PC semantics make 0x0176FFA0 the
first table word. The table stores runtime-relocated code addresses, so this
probe applies the exact relocation delta already independently closed from the
Leica R2Y assertion strings before disassembling each case.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

JUMP = 0x0176FF98
TABLE = JUMP + 8
COUNT = 17
MCC_API = 0x01B2D324
# Independently closed in M11P_261_MCC_API_IDENTITY_CLOSURE1A.md.
RUNTIME_DELTA = 0x3FAA87D0
REGION_LO = 0x01750000
REGION_HI = 0x01790000


def u32(d: bytes, a: int) -> int:
    return struct.unpack_from('<I', d, a)[0]


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
    return c


def one(c, d, a):
    xs = list(c.disasm(d[a:a+4], a, count=1))
    return xs[0] if xs else None


def target_from_text(i):
    m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', i.op_str)
    return int(m.group(1), 0) if m else None


def resolve_runtime_target(word: int) -> int:
    if REGION_LO <= word < REGION_HI:
        return word
    candidate = (word - RUNTIME_DELTA) & 0xFFFFFFFF
    return candidate


def trace_case(c, d, start, max_insns=96):
    rows = []
    calls = []
    pc = start
    seen = set()
    for _ in range(max_insns):
        if not (REGION_LO <= pc < REGION_HI) or pc in seen:
            break
        seen.add(pc)
        i = one(c, d, pc)
        if i is None:
            break
        rows.append(f'0x{pc:08X}: {i.mnemonic} {i.op_str}'.rstrip())
        bt = bl_target(pc, u32(d, pc))
        if bt is not None:
            calls.append((pc, bt)); pc += 4; continue
        m = i.mnemonic.lower(); s = i.op_str.lower()
        if m == 'blx':
            t = target_from_text(i)
            calls.append((pc, t if t is not None else -1)); pc += 4; continue
        if (m == 'bx' and s.strip() == 'lr') or (m == 'pop' and 'pc' in s) or (m.startswith('ldm') and 'pc' in s):
            break
        if m == 'b':
            t = target_from_text(i)
            if t is not None:
                rows.append(f'; terminal branch -> 0x{t:08X}')
            break
        pc += 4
    return rows, calls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    d = a.unpacked.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked SHA-256 {digest}')
    c = md()

    j = one(c, d, JUMP)
    if j is None or 'pc' not in j.op_str.lower() or '[pc' not in j.op_str.lower():
        raise RuntimeError(f'jump-table anchor mismatch: {j}')

    entries = [u32(d, TABLE + 4*n) for n in range(COUNT)]
    resolved = [resolve_runtime_target(x) for x in entries]
    lines = [
        '# M11-P 2.6.1 still R2Y mode jump table', '',
        f'- canonical SHA-256: `{digest}`',
        f'- jump: `0x{JUMP:08X}` = `{j.mnemonic} {j.op_str}`',
        f'- ARM table base: `0x{TABLE:08X}`',
        f'- runtime relocation delta: `0x{RUNTIME_DELTA:08X}`',
        f'- entries: `{COUNT}` (selector values 0..16)', '',
        '## Table', ''
    ]
    all_calls = []
    for idx, (raw, t) in enumerate(zip(entries, resolved)):
        valid = REGION_LO <= t < REGION_HI and (t & 3) == 0
        lines.append(f'- selector `{idx:2d}`: runtime `0x{raw:08X}` -> static `0x{t:08X}`' + ('' if valid else ' **INVALID**'))

    lines += ['', '## Case bodies', '']
    for idx, t in enumerate(resolved):
        lines += [f'### selector {idx} -> `0x{t:08X}`', '']
        if not (REGION_LO <= t < REGION_HI and (t & 3) == 0):
            lines += ['invalid target; not disassembled', '']; continue
        rows, calls = trace_case(c, d, t)
        all_calls.extend((idx, at, dst) for at, dst in calls)
        lines += ['```asm', *rows, '```', '']

    lines += ['## Mode-specific calls', '']
    if all_calls:
        for idx, at, dst in all_calls:
            if dst < 0:
                lines.append(f'- selector `{idx}` at `0x{at:08X}` -> indirect BLX')
            else:
                suffix = ' **MCC API**' if dst == MCC_API else ''
                lines.append(f'- selector `{idx}` at `0x{at:08X}` -> `0x{dst:08X}`{suffix}')
    else:
        lines.append('- no calls in case bodies before their terminal branch')

    mcc = [(idx, at) for idx, at, dst in all_calls if dst == MCC_API]
    lines += ['', '## MCC gate', '', f'- direct mode-case calls to `Im_R2Y_Ctrl_Multi_Axis` (`0x{MCC_API:08X}`): `{len(mcc)}`']
    for idx, at in mcc:
        lines.append(f'  - selector `{idx}` at `0x{at:08X}`')
    lines += ['', 'RENDER1H remains frozen. This probe resolves runtime jump-table targets only; it does not infer photographic behavior.', '']

    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text('\n'.join(lines) + '\n')
    print(a.output)


if __name__ == '__main__':
    main()
