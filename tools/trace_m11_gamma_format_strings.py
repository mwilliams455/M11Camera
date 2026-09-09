#!/usr/bin/env python3
"""Decode every exact-affine printable constant used by Leica M11-P gamma code.

The reconciled data/string affine base is 0x3efd2a98. Earlier analysis followed
only known gamma literals; the gamma family also constructs many 0x42b88fxx-
0x42b891xx addresses immediately before logger calls. This pass decodes all
PC-relative literal values and MOVW/MOVT constants in 0x01579338-0x01579cbc,
without preselecting strings by content.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DATA_BASE=0x3EFD2A98
START=0x01579338
END=0x01579CBC
LOGGER=0x01679B58

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def is_ldr_literal(w):return (w&0x0f7f0000)==0x051f0000
def lit(d,o,w):
    if not is_ldr_literal(w):return None
    imm=w&0xfff;p=o+8+(imm if w&0x00800000 else -imm)
    if p<0 or p+4>len(d) or p&3:return None
    return p,u32(d,p),(w>>12)&0xf
def printable(d,raw,maxlen=500):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<3:return None
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r').replace('\t','\\t')
def ann(d,v):
    raw=(v-DATA_BASE)&0xffffffff
    if raw>=len(d):return None
    s=printable(d,raw)
    return (raw,s) if s is not None else None
def disasm_map(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    return {i.address:i for i in md.disasm(d[START:END],START)}
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    im=disasm_map(d);rows=[];seen=set()
    for o in range(START&~3,END&~3,4):
        w=u32(d,o);q=lit(d,o,w)
        if q:
            pool,v,rd=q;a=ann(d,v)
            if a and (o,v) not in seen:
                seen.add((o,v));rows.append((o,'ldr-literal',f'r{rd}',v,a[0],a[1],pool))
        m=mov16(w)
        if m and m[0]=='movw':
            _,rd,lo=m
            for p in range(o+4,min(END,o+0x40)+1,4):
                m2=mov16(u32(d,p))
                if m2 and m2[0]=='movt' and m2[1]==rd:
                    v=lo|(m2[2]<<16);a=ann(d,v)
                    if a and (o,v) not in seen:
                        seen.add((o,v));rows.append((o,f'movw/movt@0x{p:08x}',f'r{rd}',v,a[0],a[1],None))
                    break
                # do not stop at unrelated instructions; generated pairs can have a few ops between halves
    lines=['# M11-P R2A complete gamma diagnostic string trace','',f'- SHA-256: `{h}`',f'- gamma range: `0x{START:08x}–0x{END:08x}`',f'- exact data/string affine: `0x{DATA_BASE:08x}`',f'- printable exact-affine constants: `{len(rows)}`','']
    for o,kind,reg,v,raw,s,pool in rows:
        near=[]
        for p in range(max(START,o-0x20),min(END,o+0x30),4):
            if bl_target(p,u32(d,p))==LOGGER:near.append(p)
        lines += [f'## `0x{o:08x}` {kind} -> `{reg}`','',f'- virtual: `0x{v:08x}` -> raw `0x{raw:08x}`',f'- text: `{s}`']
        if pool is not None:lines.append(f'- literal pool: `0x{pool:08x}`')
        if near:lines.append('- nearby logger call(s): '+', '.join(f'`0x{x:08x}`' for x in near))
        lines += ['- local instructions:','```text']
        for p in range(max(START,o-0x18),min(END,o+0x30),4):
            i=im.get(p)
            if i:
                note='';bt=bl_target(p,u32(d,p))
                if bt is not None:note=f' ; BL=0x{bt:08x}'
                lines.append(f'0x{p:08x}: {i.mnemonic} {i.op_str}{note}')
        lines += ['```','']
    lines += ['## Interpretation boundary','', 'Strings are direct terminology evidence only for the branch in which they are referenced. Format placeholders can reveal argument roles but do not by themselves prove enum meanings.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
