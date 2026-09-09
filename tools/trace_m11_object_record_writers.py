#!/usr/bin/env python3
"""Locate Leica M11-P object-record initializers and subtype writers.

The exact gamma/object analysis established a 0x210-entry table of 0x30-byte
records behind pointer global 0x433251b0. Relevant fields are:
  +0x00 byte  major type
  +0x02 half  subtype (1..6 in gamma scalar handling)
  +0x08 word  external object ID
  +0x2c word  payload pointer
This pass scans the object-management code for STRH to +0x02, groups candidate
writers by nearby function prologue, and reports local evidence for the other
record fields and immediate subtype constants. No enum semantics are assumed.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SCAN_START=0x0169C000
SCAN_END=0x016A3000
TABLE_PTR_GLOBAL=0x433251B0


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i): return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,c,r=0x900):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(SCAN_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def next_prologue(d,s,maxlen=0x1000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(SCAN_END,len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(SCAN_END,len(d),s+maxlen)
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def table_global_pairs(d,s,e):
    out=[]
    for o in range(s&~3,min(e,len(d)-4)&~3,4):
        m=mov16(u32(d,o))
        if not m or m[0]!='movw':continue
        _,rd,lo=m
        for p in range(o+4,min(e,o+0x28)+1,4):
            m2=mov16(u32(d,p))
            if m2 and m2[0]=='movt' and m2[1]==rd:
                v=lo|(m2[2]<<16)
                if v==TABLE_PTR_GLOBAL:out.append((o,p,rd))
                break
    return out
def parse_store(ins):
    # Return (width,src,base,imm) for simple str/strb/strh [base,#imm].
    if ins.mnemonic not in ('str','strb','strh'):return None
    m=re.fullmatch(r'(r\d+|ip|lr), \[(r\d+|ip|sp|lr)(?:, #(0x[0-9a-f]+|[0-9]+))?\]',ins.op_str)
    if not m:return None
    src,base,imm=m.groups();return ins.mnemonic,src,base,int(imm,0) if imm else 0
def disasm_rows(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[s:e],s):
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:note=f' ; BL=0x{bt:08x}'
        out.append((i,f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip()))
    return out
def recent_immediate(rows,idx,reg,lookback=20):
    # Exact local MOV/MOVW immediate into source register; stop on any later write
    # to same destination if easily recognizable.
    for j in range(idx-1,max(-1,idx-lookback-1),-1):
        ins=rows[j][0]
        if ins.op_str.startswith(reg+','):
            m=re.fullmatch(rf'{re.escape(reg)}, #(0x[0-9a-f]+|[0-9]+)',ins.op_str)
            if ins.mnemonic in ('mov','movw') and m:return (ins.address,int(m.group(1),0),ins.mnemonic)
            # A different obvious write means value is not a local immediate.
            if ins.mnemonic.startswith(('mov','ldr','add','sub','orr','and','eor','mul','mla')):return None
    return None
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    candidates=[]
    for ins in md.disasm(d[SCAN_START:SCAN_END],SCAN_START):
        st=parse_store(ins)
        if st and st[0]=='strh' and st[3]==2:
            candidates.append(ins.address)
    groups=defaultdict(list)
    for c in candidates:
        p=nearest_prologue(d,c) or (c&~0xff);groups[p].append(c)
    lines=['# M11-P R2A object record writer trace','',f'- SHA-256: `{h}`',f'- object table pointer global: `0x{TABLE_PTR_GLOBAL:08x}`',f'- scan: `0x{SCAN_START:08x}–0x{SCAN_END:08x}`',f'- STRH +0x02 candidate sites: `{len(candidates)}` across `{len(groups)}` prologue families','']
    for pro,sites in sorted(groups.items()):
        end=next_prologue(d,pro);rows=disasm_rows(d,pro,end);byaddr={i.address:n for n,(i,_) in enumerate(rows)}
        tg=table_global_pairs(d,pro,end)
        fieldstores=[]
        for idx,(ins,text) in enumerate(rows):
            st=parse_store(ins)
            if not st:continue
            width,src,base,imm=st
            if imm in (0,2,4,8,0x29,0x2a,0x2c):
                im=recent_immediate(rows,idx,src)
                fieldstores.append((ins.address,width,src,base,imm,im,text))
        lines += [f'## prologue candidate `0x{pro:08x}`','',f'- body bound: `0x{pro:08x}–0x{end:08x}`',f'- subtype-write site(s): '+', '.join(f'`0x{x:08x}`' for x in sites),f'- exact table-global construction(s): `{len(tg)}`']
        for a,b,r in tg:lines.append(f'  - `0x{a:08x}`/`0x{b:08x}` -> r{r} = `0x{TABLE_PTR_GLOBAL:08x}`')
        lines += ['- simple field-offset stores in body:']
        for a,w,src,base,imm,im,text in fieldstores:
            extra=f' ; recent immediate {im[1]} at 0x{im[0]:08x}' if im else ''
            lines.append(f'  - `{text}` ; offset `+0x{imm:x}`{extra}')
        lines += ['','### Windows around +0x02 writes','']
        for s in sites:
            lines += ['```text']
            for _,text in disasm_rows(d,max(pro,s-0x90),min(end,s+0x90)):lines.append(text)
            lines += ['```','']
    lines += ['## Interpretation boundary','', 'STRH +0x02 alone is only a structural candidate. Promotion to the object-record subtype initializer requires convergence with the exact table pointer/0x30 stride or with the known external-ID/payload fields in the same bounded function.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
