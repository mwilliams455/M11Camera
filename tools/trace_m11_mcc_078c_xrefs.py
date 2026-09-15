#!/usr/bin/env python3
"""Trace the unique 0x78C data lead in M11-P 2.6.1.

The prior hash-gated census found exactly one aligned 0x0000078C word, at static
image offset/address 0x0322DB4C, surrounded locally by zeroes.  0x78C is the
independently closed natural size of Milbeaut CtrlMultiAxis.  This probe asks a
narrow question: is that word part of a referenced runtime object/descriptor?

It searches direct static/runtime pointers, MOVW/MOVT address constructions in
the main ARM code region, nearby-base constructions, and reports the wider
non-zero data neighborhood.  A positive xref is still provenance evidence only,
not coefficient recovery.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

DELTA = 0x3FAA87D0
SIZE_ADDR = 0x0322DB4C
SIZE_VALUE = 0x78C
RUNTIME_ADDR = (SIZE_ADDR + DELTA) & 0xffffffff
CODE_LO = 0x01000000
CODE_HI = 0x02000000


def hits(data: bytes, value: int):
    n = struct.pack('<I', value & 0xffffffff)
    out=[]; p=0
    while True:
        p=data.find(n,p)
        if p<0: return out
        if (p&3)==0: out.append(p)
        p+=1


def parse_imm(op: str):
    m=re.search(r'#(0x[0-9a-fA-F]+|\d+)',op)
    return int(m.group(1),0) if m else None


def reg0(op: str):
    return op.split(',',1)[0].strip().lower() if op else ''


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('unpacked',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED_UNPACKED_SHA: raise ValueError(digest)

    c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    c.detail=False
    static_ptr=hits(data,SIZE_ADDR)
    runtime_ptr=hits(data,RUNTIME_ADDR)

    # Disassemble aligned ARM words only in the primary code region. Track
    # recent MOVW per register and pair with MOVT. Also record constructions of
    # any address within +/-0x1000 of the size word to expose base+offset use.
    recent={}
    exact=[]; near=[]; movt42cd=[]
    for ins in c.disasm(data[CODE_LO:CODE_HI],CODE_LO):
        if (ins.address&3)!=0: continue
        m=ins.mnemonic.lower(); r=reg0(ins.op_str); v=parse_imm(ins.op_str)
        if m=='movw' and v is not None:
            recent[r]=(ins.address,v&0xffff)
        elif m=='movt' and v is not None:
            if (v&0xffff)==((RUNTIME_ADDR>>16)&0xffff):
                movt42cd.append((ins.address,ins.op_str))
            if r in recent:
                lo_at,lo=recent[r]
                if ins.address-lo_at<=0x40:
                    x=((v&0xffff)<<16)|lo
                    rec=(lo_at,ins.address,r,x)
                    if x==RUNTIME_ADDR: exact.append(rec)
                    if abs(x-RUNTIME_ADDR)<=0x1000: near.append(rec)

    lines=[
        '# M11-P 2.6.1 unique 0x78C lead xref trace','',
        f'- canonical SHA-256: `{digest}`',
        f'- size word static: `0x{SIZE_ADDR:08X}` = `0x{SIZE_VALUE:X}`',
        f'- relocation delta: `0x{DELTA:08X}`',
        f'- corresponding runtime address: `0x{RUNTIME_ADDR:08X}`','',
        '## Raw pointer references','',
        f'- aligned words equal static address `0x{SIZE_ADDR:08X}`: `{len(static_ptr)}`',
        *[f'  - `0x{x:08X}`' for x in static_ptr[:64]],
        f'- aligned words equal runtime address `0x{RUNTIME_ADDR:08X}`: `{len(runtime_ptr)}`',
        *[f'  - `0x{x:08X}`' for x in runtime_ptr[:64]],'',
        '## ARM MOVW/MOVT constructions','',
        f'- exact runtime-address constructions: `{len(exact)}`',
    ]
    for lo,hi,r,x in exact:
        lines.append(f'- `0x{lo:08X}`..`0x{hi:08X}` `{r}` -> `0x{x:08X}`')
    lines += ['',f'- constructions within +/-0x1000: `{len(near)}`']
    for lo,hi,r,x in near[:200]:
        lines.append(f'- `0x{lo:08X}`..`0x{hi:08X}` `{r}` -> `0x{x:08X}` (delta `{x-RUNTIME_ADDR:+#x}`)')
    lines += ['',f'- MOVT instructions with high half `0x{RUNTIME_ADDR>>16:04X}`: `{len(movt42cd)}`']
    for at,op in movt42cd[:200]: lines.append(f'- `0x{at:08X}`: `movt {op}`')

    lines += ['','## Wider data neighborhood','',
              'Non-zero aligned words within +/-0x1000 of the unique size word:','', '```text']
    lo=max(0,(SIZE_ADDR-0x1000)&~3); hi=min(len(data),SIZE_ADDR+0x1004)
    nz=[]
    for off in range(lo,hi,4):
        v=struct.unpack_from('<I',data,off)[0]
        if v: nz.append((off,v))
    for off,v in nz:
        mark=' <== size' if off==SIZE_ADDR else ''
        # classify plausible runtime/static code/data pointer very conservatively
        tag=''
        st=(v-DELTA)&0xffffffff
        if CODE_LO<=st<CODE_HI: tag=f' runtime-code?->{st:#010x}'
        elif CODE_LO<=v<CODE_HI: tag=' static-code?'
        lines.append(f'0x{off:08X}: 0x{v:08X}{tag}{mark}')
    lines += ['```','',f'- non-zero words in neighborhood: `{len(nz)}`','']

    # Printable runs in same neighborhood.
    lines += ['## Nearby ASCII','']
    raw=data[lo:hi]; runs=[]; s=None
    for i,b in enumerate(raw):
        ok=0x20<=b<=0x7e
        if ok and s is None: s=i
        if (not ok or i==len(raw)-1) and s is not None:
            e=i if not ok else i+1
            if e-s>=8: runs.append((lo+s,raw[s:e].decode('ascii',errors='replace')))
            s=None
    if runs:
        for off,text in runs[:100]: lines.append(f'- `0x{off:08X}`: `{text}`')
    else: lines.append('- none')

    lines += ['','## Gate','',
              '- If there is no code/data xref and the wider region is essentially zero-filled, treat the unique 0x78C as an unproven numeric coincidence or dormant state, not the Leica MCC object.',
              '- If a coherent runtime base/xref appears, trace that owner/initializer next and test whether a 1932-byte object is copied or populated there.',
              '- RENDER1H remains frozen.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n')
    print(a.output)

if __name__=='__main__': main()
