#!/usr/bin/env python3
"""Decode exact-affine diagnostics in the Leica M11-P BB06 upstream loop.

0x0157bf34 is the sole direct caller of the BB06 R2Y master dispatcher. It
classifies received headers (BB06, BB00, 0x11, 0x22). This pass decodes every
printable data-affine constant used by that loop so subsystem naming can follow
Leica's own terminology instead of structural guesses.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
EXPECTED_SHA256='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DATA_BASE=0x3EFD2A98
START=0x0157BF34
END=0x0157C1A4

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def is_lit(w):return (w&0x0f7f0000)==0x051f0000
def lit(d,o,w):
    if not is_lit(w):return None
    imm=w&0xfff;p=o+8+(imm if w&0x00800000 else -imm)
    if p<0 or p+4>len(d) or p&3:return None
    return p,u32(d,p),(w>>12)&0xf
def printable(d,r,maxlen=500):
    if r<0 or r>=len(d):return None
    e=d.find(b'\0',r,min(len(d),r+maxlen))
    if e<=r:return None
    b=d[r:e]
    if len(b)<3:return None
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r').replace('\t','\\t')
def ann(d,v):
    r=(v-DATA_BASE)&0xffffffff
    if r>=len(d):return None
    s=printable(d,r)
    return (r,s) if s else None
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);im={i.address:i for i in md.disasm(d[START:END],START)};rows=[];seen=set()
    for o in range(START&~3,END&~3,4):
        w=u32(d,o);q=lit(d,o,w)
        if q:
            pool,v,rd=q;a=ann(d,v)
            if a and (o,v) not in seen:seen.add((o,v));rows.append((o,'literal',f'r{rd}',v,a[0],a[1],pool))
        m=mov16(w)
        if m and m[0]=='movw':
            _,rd,lo=m
            for p in range(o+4,min(END,o+0x40)+1,4):
                m2=mov16(u32(d,p))
                if m2 and m2[0]=='movt' and m2[1]==rd:
                    v=lo|(m2[2]<<16);a=ann(d,v)
                    if a and (o,v) not in seen:seen.add((o,v));rows.append((o,f'movpair@0x{p:08x}',f'r{rd}',v,a[0],a[1],None))
                    break
    lines=['# M11-P R2A upstream BB06-loop diagnostic strings','',f'- SHA-256: `{h}`',f'- loop range: `0x{START:08x}–0x{END:08x}`',f'- exact-affine printable constants: `{len(rows)}`','']
    for o,k,r,v,raw,s,pool in rows:
        lines += [f'## `0x{o:08x}` {k} -> {r}','',f'- virtual `0x{v:08x}` -> raw `0x{raw:08x}`',f'- text: `{s}`','- local instructions:','```text']
        for p in range(max(START,o-0x18),min(END,o+0x30),4):
            i=im.get(p)
            if i:lines.append(f'0x{p:08x}: {i.mnemonic} {i.op_str}')
        lines += ['```','']
    lines += ['## Interpretation boundary','', 'Decoded strings may name the loop or failure conditions. Structural packet demultiplexing remains direct evidence even if no useful strings survive.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
