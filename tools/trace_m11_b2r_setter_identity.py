#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

DELTA = 0x3FAA87D0
TARGETS = [
    0x01A62D0C, 0x01A634D8, 0x01A63A24, 0x01A63D4C, 0x01A63E68,
    0x01A6456C, 0x01A64778, 0x01A657A8, 0x01A66EA4, 0x01A66FCC,
    0x01A674E4, 0x01A677BC,
]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def bl_target(addr: int, word: int) -> int | None:
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm24 = word & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF


def callers(data: bytes, target: int) -> list[int]:
    return [p for p in range(0, len(data)-3, 4) if bl_target(p, u32(data,p)) == target]


def ascii_at(data: bytes, off: int, limit: int = 220) -> str | None:
    if not 0 <= off < len(data):
        return None
    out=[]
    for b in data[off:off+limit]:
        if b == 0:
            break
        if b in (9,10,13) or 32 <= b < 127:
            out.append(chr(b))
        else:
            return None
    s=''.join(out).strip()
    return s if len(s) >= 5 else None


def mov_pairs(insns):
    rows=[]
    for i,x in enumerate(insns):
        if x.mnemonic != 'movw' or '#' not in x.op_str:
            continue
        reg=x.op_str.split(',',1)[0].strip()
        try: lo=int(x.op_str.split('#',1)[1],0)&0xffff
        except Exception: continue
        for y in insns[i+1:i+9]:
            if y.mnemonic == 'movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
                try: hi=int(y.op_str.split('#',1)[1],0)&0xffff
                except Exception: break
                rows.append((x.address,y.address,reg,(hi<<16)|lo))
                break
    return rows


def nearest_next_prologue(md: Cs, data: bytes, start: int, limit: int = 0x5000) -> int:
    for p in range(start+4, min(len(data)-4,start+limit), 4):
        xs=list(md.disasm(data[p:p+4],p,count=1))
        if not xs: continue
        x=xs[0]; t=x.op_str.lower()
        if (x.mnemonic == 'push' and 'lr' in t) or (x.mnemonic.startswith('stm') and 'sp!' in t and 'lr' in t):
            return p
    return min(len(data), start+limit)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    data=a.unpacked.read_bytes(); digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA: raise ValueError(digest)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    lines=['# M11-P B2R setter identity trace','',f'- SHA: `{digest}`','']
    for target in TARGETS:
        end=nearest_next_prologue(md,data,target)
        ins=list(md.disasm(data[target:end],target))
        lines += [f'## `0x{target:08X}`',f'- next prologue / span end: `0x{end:08X}` (size `0x{end-target:X}`)',f'- direct callers: `{[hex(x) for x in callers(data,target)]}`','- referenced strings:']
        strings=[]
        for p,q,r,v in mov_pairs(ins):
            for off,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                s=ascii_at(data,off)
                if s:
                    row=(p,q,off,label,s)
                    if row not in strings: strings.append(row)
        if strings:
            for p,q,off,label,s in strings[:40]: lines.append(f'  - `0x{p:08X}/0x{q:08X}` {label} file `0x{off:08X}`: `{s[:190]}`')
        else:
            lines.append('  - none')
        # collect immediate register-offset constants appearing in memory/address arithmetic
        imms=[]
        for x in ins:
            if '#' in x.op_str and x.mnemonic in ('add','sub','ldr','str','ldrh','strh','ldrb','strb'):
                # retain only compact line, dedup later
                if any(k in x.op_str.lower() for k in ('0x20','0x40','0x80','0x100','0x200','0x400','0x800','0x1000','0x2000')):
                    imms.append(f'0x{x.address:08X}: {x.mnemonic} {x.op_str}')
        lines += ['- selected offset/address instructions:']
        for row in imms[:80]: lines.append(f'  - `{row}`')
        lines += ['- entry/tail disassembly:','```asm']
        show=ins[:90] + (ins[-50:] if len(ins)>140 else [])
        seen=set()
        for x in show:
            if x.address in seen: continue
            seen.add(x.address); lines.append(f'0x{x.address:08X}: {x.mnemonic} {x.op_str}')
        lines += ['```','']
    lines += ['## Decision boundary','','The Leica `img_macro_drv_b2r_set` path is rendering-relevant only if these consumers program Bayer-domain image-formation controls (e.g. offset/WB/sensitivity/interpolation/HPF) with non-default Leica values that our Android path does not already reproduce. Transport, trigger, DMA, rectangle, or output-format controls are not photographic-renderer changes.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)

if __name__=='__main__': main()
