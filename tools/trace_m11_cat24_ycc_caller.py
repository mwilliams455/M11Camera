#!/usr/bin/env python3
"""Pin the Leica Category-24 YCC resource -> Milbeaut YC register programmer path.

This is intentionally narrow and hash-gated.  The generic displacement scan found
several false positives because ordinary C structures also use +0x100/+0x104/etc.
The actual ImageMacro YC setter is identified by the same hardware traits as the
already-closed CSP setter: per-pipe F_R2Y base lookup, +0x2000 register-bank bias,
9-bit signed field packing, and writes to YC1..YC5/YBLEND.

This probe verifies the pinned setter/callsite, recovers the containing Leica
wrapper, shows r1 provenance immediately before the call, enumerates Category-24
R2YS map metadata, and compares wrapper ancestry with the known Cat42/CSP path.
It does not claim pixel-stage order from software call order alone.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R1

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y, map_bytes, sha

YC_SETTER = 0x01B624AC
YC_CALLSITE = 0x0172E238
CSP_SETTER = 0x01B68B80
CSP_CALLSITE = 0x01731DB0
EXPECTED_YCC = (77, 150, 29, -43, -85, 128, 128, -107, -21)


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
    return [off for off in range(0, len(data)-3, 4) if bl_target(off, u32(data, off)) == target]


def one_insn(md: Cs, data: bytes, off: int):
    x = list(md.disasm(data[off:off+4], off, count=1))
    return x[0] if x else None


def nearest_prologue(md: Cs, data: bytes, target: int, window: int = 0x5000) -> int:
    lo = max(0, target-window) & ~3
    hits = []
    for off in range(lo, target+1, 4):
        ins = one_insn(md, data, off)
        if not ins:
            continue
        t = ins.op_str.lower()
        if (ins.mnemonic == 'push' and 'lr' in t) or (ins.mnemonic.startswith('stm') and 'sp!' in t and 'lr' in t):
            hits.append(off)
    if not hits:
        raise RuntimeError(f'no prologue before {target:#x}')
    return hits[-1]


def function_instructions(md: Cs, data: bytes, entry: int, through: int, max_len: int = 0x6000):
    out=[]; passed=False
    for ins in md.disasm(data[entry:min(len(data),entry+max_len)], entry):
        out.append(ins)
        if ins.address >= through:
            passed=True
        if passed:
            t=(ins.mnemonic+' '+ins.op_str).lower()
            if (ins.mnemonic=='pop' and 'pc' in ins.op_str.lower()) or t.startswith('bx lr') or (ins.mnemonic.startswith('ldm') and 'pc' in ins.op_str.lower()):
                break
    return out


def fmt(ins):
    return f'0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}'.rstrip()


def r1_writers(insns, callsite):
    rows=[]
    for ins in insns:
        if ins.address >= callsite: break
        try: _,writes=ins.regs_access()
        except Exception: writes=[]
        if ARM_REG_R1 in writes: rows.append(ins)
    return rows


def cat_maps(data: bytes, category: int):
    base,_,_,descs=parse_r2y(data)
    out=[]
    for d in descs:
        if d['category'] != category: continue
        raw=map_bytes(data,base,d)
        out.append((d,raw))
    return out


def wrapper_info(md: Cs, data: bytes, setter: int, callsite: int):
    if bl_target(callsite,u32(data,callsite)) != setter:
        raise ValueError(f'callsite {callsite:#x} no longer targets {setter:#x}')
    entry=nearest_prologue(md,data,callsite)
    insns=function_instructions(md,data,entry,callsite)
    return entry,insns,direct_callers(data,entry)


def parent_entries(md: Cs, data: bytes, calls: list[int]) -> dict[int,list[int]]:
    out={}
    for call in calls:
        try: e=nearest_prologue(md,data,call,0x5000)
        except RuntimeError: continue
        out.setdefault(e,[]).append(call)
    return out


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    data=a.unpacked.read_bytes(); digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA: raise ValueError(digest)

    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    y_entry,y_ins,y_parent_calls=wrapper_info(md,data,YC_SETTER,YC_CALLSITE)
    c_entry,c_ins,c_parent_calls=wrapper_info(md,data,CSP_SETTER,CSP_CALLSITE)
    y_writers=r1_writers(y_ins,YC_CALLSITE)
    c_writers=r1_writers(c_ins,CSP_CALLSITE)
    y_parents=parent_entries(md,data,y_parent_calls)
    c_parents=parent_entries(md,data,c_parent_calls)
    common=sorted(set(y_parents)&set(c_parents))

    maps=cat_maps(data,24)
    if len(maps) != 1: raise ValueError(f'expected one Cat24 descriptor, got {len(maps)}')
    d,raw=maps[0]
    if len(raw)!=18: raise ValueError(f'Cat24 map size {len(raw)} != 18')
    vals=struct.unpack('<9h',raw)
    if vals != EXPECTED_YCC: raise ValueError(f'Cat24 matrix mismatch {vals}')

    # Hard traits proving YC_SETTER is the hardware programmer, not a displacement coincidence.
    setter_text='\n'.join(fmt(i) for i in md.disasm(data[YC_SETTER:YC_SETTER+0x700],YC_SETTER))
    required=('#0x2000','#0x100','#0x104','#0x108','#0x10c','#0x110','#0x120')
    missing=[x for x in required if x not in setter_text]
    if missing: raise ValueError(f'YC setter hardware footprint guard missing {missing}')

    lines=['# M11-P Category-24 YC caller/resource trace','',
           f'- unpacked SHA-256: `{digest}`',
           f'- pinned YC hardware setter: `0x{YC_SETTER:08x}`',
           f'- sole known direct YC callsite: `0x{YC_CALLSITE:08x}`',
           f'- containing YC wrapper entry: `0x{y_entry:08x}`',
           f'- pinned CSP hardware setter: `0x{CSP_SETTER:08x}`',
           f'- pinned CSP callsite: `0x{CSP_CALLSITE:08x}`',
           f'- containing CSP wrapper entry: `0x{c_entry:08x}`','']

    lines += ['## Category-24 resource','',
              f'- descriptor index: `{d["index"]}`', f'- descriptor size: `{d["descriptor_size"]}`',
              f'- map size: `{d["map_size"]}`', f'- map offset: `0x{d["map_offset_abs"]:08x}`',
              f'- dependencies: `{d["dependencies_s32"]}`', f'- map SHA-256: `{sha(raw)}`',
              f'- int16 matrix words: `{list(vals)}`',
              '- matrix: `[[77,150,29],[-43,-85,128],[128,-107,-21]] / 256`','']

    lines += ['## YC wrapper ancestry','',f'- direct callers of YC wrapper: `{len(y_parent_calls)}`']
    for x in y_parent_calls[:64]: lines.append(f'  - `0x{x:08x}`')
    lines += ['', '## CSP wrapper ancestry','',f'- direct callers of CSP wrapper: `{len(c_parent_calls)}`']
    for x in c_parent_calls[:64]: lines.append(f'  - `0x{x:08x}`')
    lines += ['', '## Shared immediate parent functions','',f'- count: `{len(common)}`']
    for e in common:
        lines.append(f'- `0x{e:08x}` YC callsites `{[hex(x) for x in y_parents[e]]}` CSP callsites `{[hex(x) for x in c_parents[e]]}`')

    lines += ['', '## r1 provenance immediately before YC setter call','']
    for i in y_writers[-32:]: lines.append(f'- `{fmt(i)}`')
    if y_writers: lines += ['',f'Nearest r1 writer: `{fmt(y_writers[-1])}`']
    lines += ['', '## YC wrapper context','', '```asm']
    before=[i for i in y_ins if i.address<YC_CALLSITE][-120:]; after=[i for i in y_ins if i.address>=YC_CALLSITE][:48]
    lines += [fmt(i) for i in before+after]; lines += ['```','']

    lines += ['## r1 provenance immediately before CSP setter call','']
    for i in c_writers[-20:]: lines.append(f'- `{fmt(i)}`')
    if c_writers: lines += ['',f'Nearest r1 writer: `{fmt(c_writers[-1])}`']

    if common:
        lines += ['', '## Shared-parent contexts','']
        for e in common[:4]:
            lines += [f'### `0x{e:08x}`','', '```asm']
            ins=function_instructions(md,data,e,max(y_parents[e]+c_parents[e]))
            lo=min(y_parents[e]+c_parents[e])-0x100; hi=max(y_parents[e]+c_parents[e])+0x100
            lines += [fmt(i) for i in ins if lo<=i.address<=hi]; lines += ['```','']

    lines += ['## Decision boundary','',
              'A direct 18-byte Category-24 record passed to the pinned YC setter closes the Leica resource -> YC register-programmer mapping. Shared software ancestry/order is configuration evidence only. Pixel-stage order must still be based on the public Milbeaut block semantics/register topology: YC is the RGB-to-Y/C conversion block and CSP is a luminance/chroma-referenced chroma-suppression block. If the resource mapping closes and no contrary data-flow evidence appears, the existing renderer placement (YC before CSP, CSP using converted Y) is supported and no RENDER1I placement experiment is justified.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)); print(a.output)

if __name__=='__main__': main()
