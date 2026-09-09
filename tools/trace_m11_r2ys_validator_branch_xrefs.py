#!/usr/bin/env python3
"""Find every static A32 transfer/address construction for R2YS validator 0x0178af24.

Previous scans covered direct BL and stored function-pointer words. This closes
remaining common static encodings: B/BL/BLX immediate, ADR-style ADD/SUB from
PC, and MOVW/MOVT construction of either the raw code address or the proven
translated code pointer.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import deque
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

EXPECTED=EXPECTED_UNPACKED_SHA
TARGET=0x0178AF24
CODEPTR_BASE=0x3FAA87D0
TPTR=(TARGET+CODEPTR_BASE)&0xffffffff
CODE_START=0x01000000
CODE_END=0x02000000


def is_prologue(i):return i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,a,r=0x1600):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for p in range(max(CODE_START,a-r)&~3,a+1,4):
        i=next(md.disasm(d[p:p+4],p),None)
        if i and is_prologue(i):best=p
    return best
def imm(op):
    m=re.search(r'#(-?0x[0-9a-f]+|-?[0-9]+)',op)
    return int(m.group(1),0) if m else None
def context(d,a,r=0x40):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    s=max(CODE_START,a-r)&~3;e=min(CODE_END,len(d),a+r+4)
    return [f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip() for i in md.disasm(d[s:e],s)]
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    transfers=[];adr=[];pairs=[];recent={};idx=0
    for i in md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START):
        idx+=1
        # Direct immediate branch/call forms as decoded by Capstone.
        if i.mnemonic in ('b','bl','blx') and i.op_str.startswith('#'):
            v=imm(i.op_str)
            if v==TARGET:transfers.append((i.address,i.mnemonic,i.op_str))
        # ADR-style raw target construction: ARM PC value is address+8.
        if i.mnemonic in ('add','sub'):
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==3 and p[1]=='pc':
                v=imm(p[2])
                if v is not None:
                    got=((i.address+8)+v if i.mnemonic=='add' else (i.address+8)-v)&0xffffffff
                    if got in (TARGET,TPTR):adr.append((i.address,i.mnemonic,i.op_str,got))
        if i.mnemonic=='movw':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2:
                v=imm(p[1])
                if v is not None:recent[p[0]]=(idx,i.address,v&0xffff)
        elif i.mnemonic=='movt':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2 and p[0] in recent:
                j,a,lo=recent[p[0]];hi=imm(p[1])
                if hi is not None and idx-j<=16:
                    got=((hi&0xffff)<<16)|lo
                    if got in (TARGET,TPTR):pairs.append((a,i.address,p[0],got))
        for r,(j,_,_) in list(recent.items()):
            if idx-j>20:recent.pop(r,None)
    lines=['# M11-P R2A validator static branch/address xrefs','',f'- SHA-256: `{h}`',f'- validator raw: `0x{TARGET:08x}`',f'- translated pointer: `0x{TPTR:08x}`','', '## Direct B/BL/BLX-immediate transfers','',f'- count: `{len(transfers)}`']
    for a,m,o in transfers:
        lines.append(f'### `0x{a:08x}: {m} {o}` — prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
        lines+=['```text'];lines.extend(context(d,a));lines+=['```','']
    lines += ['## ADR-style PC-relative constructions','',f'- count: `{len(adr)}`']
    for a,m,o,v in adr:
        lines.append(f'- `0x{a:08x}: {m} {o}` -> `0x{v:08x}`; prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
    lines += ['', '## MOVW/MOVT constructions','',f'- count: `{len(pairs)}`']
    for a,b,r,v in pairs:
        lines.append(f'- `0x{a:08x}`..`0x{b:08x}` `{r}` -> `0x{v:08x}`; prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
        lines+=['```text'];lines.extend(context(d,a));lines+=['```','']
    lines += ['## Interpretation boundary','', 'If all three classes are zero, no ordinary static A32 call/address materialization reaches the validator. Invocation is then likely via a runtime-computed module-relative entry, overlay/dispatch mechanism, or non-A32 execution domain; the next target should be the resource-owner/type-index dispatch rather than further literal xrefs.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
