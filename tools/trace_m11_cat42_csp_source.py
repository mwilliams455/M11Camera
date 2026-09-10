#!/usr/bin/env python3
"""Trace the source pointer feeding Leica's Category-42 CSP wrapper.

Pinned firmware facts from prior probes:
  CSP HW register programmer : 0x01b68b80
  sole direct callsite       : 0x01731db0
  containing wrapper entry   : 0x01731970
  wrapper source slot        : [fp, #-8]
  wrapper local CSP struct   : [fp, #-0x34] (44 bytes)

This probe identifies every write to [fp,-8], expands the entry-to-call control
flow, and searches A32 B/BL as well as aligned function-pointer references to
the wrapper. It changes no renderer behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_FP, ARM_REG_R11

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

FUNC = 0x01731970
CALL = 0x01731DB0
CSP = 0x01B68B80


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def branch_target(addr: int, w: int):
    cond = (w >> 28) & 0xF
    op = (w >> 24) & 0xF
    if cond == 0xF or op not in (0xA, 0xB):
        return None, None
    imm24 = w & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF, ('BL' if op == 0xB else 'B')


def fmt(ins):
    return f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}".rstrip()


def is_fp_minus8_write(ins) -> bool:
    # Capstone detail marks memory operands; instruction must write memory.
    if not ins.mnemonic.startswith(('str', 'stm')):
        return False
    for op in ins.operands:
        if op.type == ARM_OP_MEM:
            base = op.mem.base
            if base in (ARM_REG_FP, ARM_REG_R11) and op.mem.disp == -8:
                return True
    return False


def all_xrefs(data: bytes, target: int):
    b, bl = [], []
    for off in range(0, len(data)-3, 4):
        t, kind = branch_target(off, u32(data, off))
        if t == target:
            (bl if kind == 'BL' else b).append(off)
    ptr = []
    ptr_thumb = []
    for off in range(0, len(data)-3, 4):
        v = u32(data, off)
        if v == target:
            ptr.append(off)
        if v == (target | 1):
            ptr_thumb.append(off)
    return b, bl, ptr, ptr_thumb


def category42(data: bytes):
    _, _, _, ds = parse_r2y(data)
    out=[]
    for d in ds:
        if d.get('category') != 42:
            continue
        deps=d.get('dependencies_s32',[])
        out.append({
            'state': deps[2] if len(deps)>=3 else None,
            'map_offset_abs': d.get('map_offset_abs'),
            'map_size': d.get('map_size'),
        })
    return sorted(out, key=lambda x: 999 if x['state'] is None else x['state'])


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('unpacked',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    data=args.unpacked.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked SHA {digest}')
    t,k=branch_target(CALL,u32(data,CALL))
    if t != CSP or k != 'BL':
        raise ValueError('pinned CSP call no longer valid')

    md=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    insns=list(md.disasm(data[FUNC:CALL+4], FUNC))
    slot_writes=[i for i in insns if is_fp_minus8_write(i)]
    b,bl,ptr,ptr_thumb=all_xrefs(data,FUNC)
    maps=category42(data)
    map_offsets={x['map_offset_abs'] for x in maps if x['map_offset_abs'] is not None}

    lines=[
        '# M11-P Category-42 CSP source-pointer trace','',
        f'- exact unpacked SHA-256: `{digest}`',
        f'- wrapper entry: `0x{FUNC:08x}`',
        f'- CSP callsite: `0x{CALL:08x}` -> `0x{CSP:08x}`',
        f'- instructions decoded entry-to-call: `{len(insns)}`',
        f'- writes to `[fp,-8]`: `{len(slot_writes)}`',
        f'- direct A32 B xrefs to wrapper: `{len(b)}`',
        f'- direct A32 BL xrefs to wrapper: `{len(bl)}`',
        f'- aligned words equal wrapper address: `{len(ptr)}`',
        f'- aligned words equal wrapper|1: `{len(ptr_thumb)}`','',
        '## Wrapper xrefs',''
    ]
    for kind,vals in [('B',b),('BL',bl),('PTR',ptr),('PTR_THUMB',ptr_thumb)]:
        for x in vals[:128]: lines.append(f'- {kind}: `0x{x:08x}`')

    lines += ['', '## Writes to source slot `[fp,-8]`', '']
    if not slot_writes:
        lines.append('- none found in decoded entry-to-call region')
    for sw in slot_writes:
        idx=next(i for i,x in enumerate(insns) if x.address==sw.address)
        lines += [f'### write at `0x{sw.address:08x}`','', '```asm']
        lines += [fmt(x) for x in insns[max(0,idx-24):min(len(insns),idx+12)]]
        lines += ['```','']

    lines += ['## Function entry and early setup','', '```asm']
    lines += [fmt(x) for x in insns[:180]]
    lines += ['```','']

    lines += ['## Last 96 instructions before CSP call','', '```asm']
    lines += [fmt(x) for x in insns[-96:]]
    lines += ['```','']

    # Scan constants loaded by MOVW/MOVT is easier to interpret with raw text;
    # additionally report aligned words that equal known Cat42 file offsets.
    lines += ['## Category-42 map offsets and aligned references','',
              '| state | map file offset | size | aligned words containing exact offset |','|---:|---:|---:|---|']
    for m in maps:
        off=m['map_offset_abs']; refs=[]
        if off is not None:
            for p in range(0,len(data)-3,4):
                if u32(data,p)==off:
                    refs.append(p)
        st='?' if m['state'] is None else f"{m['state']:+d}"
        o='?' if off is None else f'0x{off:08x}'
        lines.append(f"| {st} | `{o}` | {m['map_size']} | {', '.join(f'`0x{x:08x}`' for x in refs[:32]) or 'none'} |")

    lines += ['', '## Interpretation boundary','',
              'A write to `[fp,-8]` establishes the immediate source-pointer provenance for the wrapper. Direct B/BL and pointer references help identify how the wrapper is entered when no ordinary BL caller exists. File-offset equality is only a locator clue: runtime resource pointers may be relocated or produced from descriptor structures. This probe does not infer the Milbeaut CSP pixel equation.','']
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text('\n'.join(lines))
    print(args.output)

if __name__=='__main__': main()
