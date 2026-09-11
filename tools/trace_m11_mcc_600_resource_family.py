#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, map_bytes, parse_r2y

RESOLVER = 0x0178D0A8
TARGET_CATEGORIES = {16, 17}
MAP_SIZE = 600
AREA_BYTES = 150
AREA_WORDS = 75
MCK_WORDS = 45
MCL_WORDS = 30


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def bl_target(addr: int, word: int) -> int | None:
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm24 = word & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF


def direct_callers(data: bytes, target: int) -> list[int]:
    return [off for off in range(0, len(data) - 3, 4) if bl_target(off, u32(data, off)) == target]


def nearest_prologue(md: Cs, data: bytes, target: int, window: int = 0x6000) -> int | None:
    lo = max(0, target - window) & ~3
    best = None
    for off in range(lo, target + 1, 4):
        ins = list(md.disasm(data[off:off+4], off, count=1))
        if not ins:
            continue
        x = ins[0]
        t = x.op_str.lower()
        if (x.mnemonic == 'push' and 'lr' in t) or (x.mnemonic.startswith('stm') and 'sp!' in t and 'lr' in t):
            best = off
    return best


def fmt(ins) -> str:
    return f'0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}'.rstrip()


def stats(vals: tuple[int, ...] | list[int]) -> str:
    vals = list(vals)
    c = Counter(vals)
    return (
        f'n={len(vals)} min={min(vals)} max={max(vals)} zeros={c[0]} '
        f'abs<=8={sum(abs(x)<=8 for x in vals)} abs<=64={sum(abs(x)<=64 for x in vals)} '
        f'abs<=512={sum(abs(x)<=512 for x in vals)} unique={len(c)}'
    )


def hash_words(vals: list[int]) -> str:
    raw = struct.pack('<' + 'h'*len(vals), *vals)
    return hashlib.sha256(raw).hexdigest()


def resolver_contexts(md: Cs, data: bytes) -> list[tuple[int, int | None, list]]:
    out = []
    for call in direct_callers(data, RESOLVER):
        entry = nearest_prologue(md, data, call)
        lo = max(entry or call - 0x400, call - 0x500)
        ins = list(md.disasm(data[lo:call+4], lo))
        # Find immediate category stores. Known Leica request ABI stores category at request+8.
        hits = []
        for i, x in enumerate(ins):
            if x.mnemonic not in ('str', 'strh', 'strb') or len(x.operands) < 2:
                continue
            src, mem = x.operands[0], x.operands[1]
            if src.type != ARM_OP_REG or mem.type != ARM_OP_MEM:
                continue
            r = x.reg_name(src.reg)
            # Search a few instructions backward for MOV/MOVW immediate into the same register.
            val = None
            for y in reversed(ins[max(0, i-6):i]):
                if len(y.operands) >= 2 and y.operands[0].type == ARM_OP_REG and y.reg_name(y.operands[0].reg) == r:
                    if y.mnemonic in ('mov', 'movw') and y.operands[1].type == ARM_OP_IMM:
                        val = int(y.operands[1].imm) & 0xFFFFFFFF
                    break
            if val in TARGET_CATEGORIES:
                hits.append((x.address, val))
        if hits:
            out.append((call, entry, ins))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked hash {digest}')

    base, _, _, descs = parse_r2y(data)
    maps = [d for d in descs if d['map_size'] == MAP_SIZE]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    lines = [
        '# M11-P 600-byte R2YS / MCC geometry probe', '',
        f'- unpacked SHA-256: `{digest}`',
        f'- 600-byte descriptors: `{len(maps)}`',
        '- MCC geometry hypothesis: `600 bytes = 4 * 150-byte areas`, each area = `45 int16 MCK + 30 int16 MCL`.',
        '- Three consecutive 600-byte maps would therefore carry all 12 areas / 1800 coefficient bytes if this family is MCC.', '',
        '## Descriptor inventory', ''
    ]

    for d in maps:
        raw = map_bytes(data, base, d)
        vals = list(struct.unpack('<300h', raw))
        lines += [
            f'### descriptor `{d["index"]}` category `{d["category"]}`',
            f'- flags: `{d["flags_hex"]}` descriptor size `{d["descriptor_size"]}`',
            f'- dependencies: `{d["dependencies_s32"]}`',
            f'- map offset: `0x{d["map_offset_abs"]:08X}`',
            f'- SHA-256: `{hashlib.sha256(raw).hexdigest()}`',
            f'- whole-map stats: `{stats(vals)}`',
            f'- first 24 i16: `{vals[:24]}`',
            f'- last 24 i16: `{vals[-24:]}`',
        ]
        for area in range(4):
            av = vals[area*AREA_WORDS:(area+1)*AREA_WORDS]
            mck = av[:MCK_WORDS]
            mcl = av[MCK_WORDS:]
            lines += [
                f'- area {area}: MCK `{stats(mck)}` SHA `{hash_words(mck)[:16]}`; MCL `{stats(mcl)}` SHA `{hash_words(mcl)[:16]}`',
                f'  - MCK head/tail: `{mck[:10]}` ... `{mck[-10:]}`',
                f'  - MCL head/tail: `{mcl[:10]}` ... `{mcl[-10:]}`',
            ]
        lines.append('')

    # Group contiguous triples. Require physically adjacent map offsets as well as descriptor adjacency.
    lines += ['## Consecutive 3x600 groups', '']
    by_index = {d['index']: d for d in maps}
    groups = []
    for d in maps:
        ds = [by_index.get(d['index'] + k) for k in range(3)]
        if not all(ds):
            continue
        if ds[1]['map_offset_abs'] != ds[0]['map_offset_abs'] + 600 or ds[2]['map_offset_abs'] != ds[1]['map_offset_abs'] + 600:
            continue
        key = tuple(x['index'] for x in ds)
        if key not in groups:
            groups.append(key)
            lines += [
                f'- descriptors `{key}` categories `{[x["category"] for x in ds]}` flags `{[x["flags_hex"] for x in ds]}`',
                f'  - dependencies: `{[x["dependencies_s32"] for x in ds]}`',
                f'  - combined map span: `0x{ds[0]["map_offset_abs"]:08X}..0x{ds[2]["map_offset_abs"]+600:08X}` (1800 bytes)',
            ]
    if not groups:
        lines.append('- none')

    lines += ['', '## Resolver callsites with nearby category-16/17 immediate stores', '']
    contexts = resolver_contexts(md, data)
    lines.append(f'- resolver direct callsites with candidate nearby stores: `{len(contexts)}`')
    for call, entry, ins in contexts:
        lines += [f'### call `0x{call:08X}` function `{hex(entry) if entry is not None else "unknown"}`', '```asm']
        # Keep the final 140 instructions before each resolver call; enough to expose request construction.
        for x in ins[-140:]:
            lines.append(fmt(x))
        lines += ['```', '']

    lines += [
        '## Decision boundary', '',
        'A 600-byte size match alone is not sufficient. Promote this family to MCC only if (1) the 4x75-word split yields coefficient-like structure, (2) three adjacent maps form a coherent 12-area set under the same selector/dependency family, and (3) Leica code routes those resources into the closed MultiAxis/MCC control path or into an object with the exact MCK/MCL field geometry.', ''
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(lines) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
