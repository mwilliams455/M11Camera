#!/usr/bin/env python3
"""Trace Leica-primary helper routines used by the exact gamma selector family.

The gamma candidate calls several nearby/general routines whose semantics are
more useful than generic public-source byte matching. This pass inventories
all direct A32 callers, argument setup windows, target bodies and callees for:

  0x015a6374  -- called with r2=0x1400 in the gamma path
  0x0169e6ec / 0x0169e748 / 0x0169e7a4 -- adjacent object/parser helpers
  0x0169d980  -- repeatedly used by YC/gamma selector code
  0x01579264  -- local selector/helper used before gamma transfer paths

Names remain deliberately descriptive/provisional until semantics converge.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SCAN_START=0x01000000
SCAN_END=0x02000000
TARGETS={
    "gamma_bulk_1400":0x015A6374,
    "gamma_local_helper":0x01579264,
    "object_helper_e6ec":0x0169E6EC,
    "object_helper_e748":0x0169E748,
    "object_helper_e7a4":0x0169E7A4,
    "selector_helper_d980":0x0169D980,
}


def u32(data:bytes,off:int)->int:
    return struct.unpack_from('<I',data,off)[0]


def bl_target(off:int,w:int)->int|None:
    if (w & 0x0F000000)!=0x0B000000:
        return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=0x1000000
    return off+8+(imm<<2)


def is_prologue(ins)->bool:
    return ins is not None and ins.mnemonic in ('push','stmdb') and 'lr' in ins.op_str and (ins.mnemonic=='push' or 'sp' in ins.op_str)


def nearest_prologue(data:bytes,center:int,radius:int=0x1000)->int|None:
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    best=None
    for off in range(max(SCAN_START,center-radius)&~3,center+1,4):
        ins=next(md.disasm(data[off:off+4],off),None)
        if is_prologue(ins): best=off
    return best


def next_prologue(data:bytes,start:int,max_len:int=0x1000)->int:
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for off in range(start+4,min(len(data)-4,start+max_len),4):
        ins=next(md.disasm(data[off:off+4],off),None)
        if is_prologue(ins): return off
    return min(len(data),start+max_len)


def all_callers(data:bytes,target:int)->list[int]:
    out=[]
    for off in range(SCAN_START,min(SCAN_END,len(data)-4)&~3,4):
        if bl_target(off,u32(data,off))==target: out.append(off)
    return out


def disasm_lines(data:bytes,start:int,end:int,max_ins:int|None=None)->list[str]:
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True
    out=[]
    for i,ins in enumerate(md.disasm(data[max(0,start):min(len(data),end)],max(0,start))):
        if max_ins is not None and i>=max_ins: break
        note=''
        if ins.address+4<=len(data) and not(ins.address&3):
            bt=bl_target(ins.address,u32(data,ins.address))
            if bt is not None: note=f' ; BL=0x{bt:08x}'
        out.append(f'0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}{note}'.rstrip())
    return out


def immediate_arg_summary(data:bytes,call:int,lookback:int=0x50)->list[str]:
    """Collect last obvious immediate write to r0-r3 before a call.

    Diagnostic only: this does not perform full data-flow. It is useful for
    spotting repeated size/type constants such as r2=0x1400 across callers.
    """
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    last={}
    for ins in md.disasm(data[max(SCAN_START,call-lookback):call],max(SCAN_START,call-lookback)):
        m=re.fullmatch(r'(r[0-3]), #(0x[0-9a-f]+|[0-9]+)',ins.op_str)
        if ins.mnemonic.startswith('mov') and m:
            last[m.group(1)]=(ins.address,int(m.group(2),0),ins.mnemonic)
    return [f'{reg}=0x{val:x} at 0x{off:08x} ({mn})' for reg,(off,val,mn) in sorted(last.items())]


def target_report(data:bytes,label:str,target:int)->list[str]:
    callers=all_callers(data,target)
    end=next_prologue(data,target,0x1000)
    callees=Counter()
    for off in range(target,end,4):
        bt=bl_target(off,u32(data,off))
        if bt is not None: callees[bt]+=1
    lines=[
        f'## `{label}` target `0x{target:08x}`', '',
        f'- target-body next-prologue bound: `0x{target:08x}–0x{end:08x}` (`0x{end-target:x}` bytes)',
        f'- direct A32 callers: `{len(callers)}`',
        f'- direct target-body callees: `{len(callees)}`',
    ]
    for t,n in callees.most_common(20): lines.append(f'  - `0x{t:08x}`: `{n}` call(s)')
    lines += ['', '### Target body (derived A32 disassembly)', '', '```text']
    lines.extend(disasm_lines(data,target,end,180)); lines += ['```','', '### Caller windows','']
    for c in callers[:80]:
        pro=nearest_prologue(data,c)
        lines.append(f'#### call `0x{c:08x}` / prologue `{("0x%08x"%pro) if pro else "unknown"}`')
        args=immediate_arg_summary(data,c)
        if args: lines.append('- recent obvious immediate arg writes: '+', '.join(f'`{x}`' for x in args))
        lines.append('```text')
        lines.extend(disasm_lines(data,max(SCAN_START,c-0x50),c+0x10,28))
        lines += ['```','']
    return lines


def report(data:bytes)->str:
    digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED_SHA256: raise ValueError(f'unexpected M11-P SHA-256 {digest}')
    lines=['# M11-P R2A gamma helper call/caller trace','',f'- SHA-256: `{digest}`','- Labels are provisional descriptions, not recovered Leica symbols.','']
    for label,target in TARGETS.items(): lines.extend(target_report(data,label,target))
    lines += ['## Interpretation boundary','', 'Argument summaries report only obvious immediate writes in the local window; register values carried from earlier blocks are not inferred. Helper semantics are promoted only from repeated caller patterns plus target-body behavior.','']
    return '\n'.join(lines)


def main()->None:
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)

if __name__=='__main__': main()
