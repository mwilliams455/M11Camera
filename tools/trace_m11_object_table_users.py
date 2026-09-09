#!/usr/bin/env python3
"""Map Leica M11-P users/loaders of the proven object-table pointer global.

The object accessor family proves global 0x433251b0 points to 0x210 records of
0x30 bytes. Direct STRH +2 writers were absent, so this pass finds every exact
MOVW/MOVT construction of 0x433251b0 in the object-management region, groups
uses by function, and reports stores, bulk-copy calls and 0x30-stride arithmetic.
It also separately identifies writes to the pointer global itself.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import defaultdict, Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
GLOBAL=0x433251B0
SCAN_START=0x01698000
SCAN_END=0x016A6000


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,c,r=0x1400):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(SCAN_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def next_prologue(d,s,maxlen=0x1800):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(SCAN_END,len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(SCAN_END,len(d),s+maxlen)
def global_pairs(d):
    out=[]
    for o in range(SCAN_START&~3,min(SCAN_END,len(d)-4)&~3,4):
        m=mov16(u32(d,o))
        if not m or m[0]!='movw':continue
        _,rd,lo=m
        for p in range(o+4,min(SCAN_END,o+0x30)+1,4):
            m2=mov16(u32(d,p))
            if m2 and m2[0]=='movt' and m2[1]==rd:
                if (lo|(m2[2]<<16))==GLOBAL:out.append((o,p,rd))
                break
    return out
def rows(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[s:e],s):
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:note=f' ; BL=0x{bt:08x}'
        out.append((i,f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip()))
    return out
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    pairs=global_pairs(d);groups=defaultdict(list)
    for a,b,r in pairs:
        p=nearest_prologue(d,a) or (a&~0xff);groups[p].append((a,b,r))
    lines=['# M11-P R2A object table users / loader trace','',f'- SHA-256: `{h}`',f'- exact object-table pointer global: `0x{GLOBAL:08x}`',f'- exact global constructions: `{len(pairs)}` across `{len(groups)}` function families','']
    for pro,uses in sorted(groups.items()):
        end=next_prologue(d,pro);body=rows(d,pro,end);calls=Counter();stores=[];stride=[];global_store=[]
        constructed_regs={r for _,_,r in uses}
        for ins,text in body:
            if ins.address+4<=len(d):
                bt=bl_target(ins.address,u32(d,ins.address))
                if bt is not None:calls[bt]+=1
            if ins.mnemonic.startswith('str'):stores.append(text)
            if '#0x30' in ins.op_str or '#0x210' in ins.op_str:stride.append(text)
            # Flag explicit STR whose base register is one of the registers that
            # held &GLOBAL. This is conservative and local, but useful for spotting
            # pointer installation routines.
            for r in constructed_regs:
                rn=f'r{r}'
                if ins.mnemonic=='str' and re.search(rf'\[{rn}(?:, #0)?\]',ins.op_str):
                    global_store.append(text)
        lines += [f'## prologue candidate `0x{pro:08x}`','',f'- bound: `0x{pro:08x}–0x{end:08x}`','- &GLOBAL constructions:']
        for a,b,r in uses:lines.append(f'  - `0x{a:08x}`/`0x{b:08x}` -> r{r}')
        lines.append(f'- explicit store(s) through an &GLOBAL register: `{len(global_store)}`')
        for x in global_store:lines.append(f'  - `{x}`')
        lines.append(f'- 0x30/0x210 structural instructions: `{len(stride)}`')
        for x in stride:lines.append(f'  - `{x}`')
        lines.append(f'- direct callees: `{len(calls)}`')
        for t,n in calls.most_common(30):lines.append(f'  - `0x{t:08x}`: `{n}`')
        lines += ['','### Stores in bounded body','']
        for x in stores[:160]:lines.append(f'- `{x}`')
        lines += ['','### Full bounded body','```text'];lines.extend(x for _,x in body);lines += ['```','']
    lines += ['## Interpretation boundary','', 'A write through the register holding &0x433251b0 is strong evidence for table-pointer installation. Record-population semantics require 0x30-stride or known field writes/copies in the same bounded path.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
