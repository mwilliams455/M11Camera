#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,re,struct
from pathlib import Path
from collections import defaultdict
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM,ARM_OP_MEM
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000;END=0x02000000
FIELDS={0x1f8:'block_1f8',0x250:'cm1_frame',0x278:'cm2_frame',0x2a0:'block_2a0'}
GLOBAL=0x43430188

def u32(d,a):
    return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def ispush(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def fstart(d,a,win=0x20000):
    for p in range(a&~3,max(START,(a&~3)-win),-4):
        if ispush(u32(d,p)):return p
    return max(START,a-0x1000)
def callers(code,t):
    out=[]
    for q in range(0,len(code)-3,4):
        if bt(START+q,struct.unpack_from('<I',code,q)[0])==t:out.append(START+q)
    return out
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def decode_mov16(w,kind):
    tag=w&0x0ff00000;want=0x03000000 if kind=='movw' else 0x03400000
    if tag!=want:return None
    return (w>>12)&0xf,(((w>>4)&0xf000)|(w&0xfff))
def movrefs(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        m=decode_mov16(struct.unpack_from('<I',code,q)[0],'movw')
        if not m:continue
        rd,lo=m
        for r in range(q+4,min(q+36,len(code)-3),4):
            mt=decode_mov16(struct.unpack_from('<I',code,r)[0],'movt')
            if mt and mt[0]==rd:
                if ((mt[1]<<16)|lo)==target:out.append((START+q,START+r,rd))
                break
    return out
def strings_in(d,lo,hi):
    for m in re.finditer(rb'[\x20-\x7e]{4,}\x00',d[lo:hi]):
        yield lo+m.start(),m.group()[:-1].decode('ascii','replace')
def dis(md,d,lo,hi):return list(md.disasm(d[lo:hi],lo))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P ColorSpec frame consumer trace','',f'- SHA256 `{h}`','']
    L+=['## CM debug strings around live copier','']
    for p,s in strings_in(d,0x0277B880,0x0277BE20):L.append(f'- `0x{p:08X}` `{s}`')

    L+=['','## Global ColorSpec object direct MOVW/MOVT references','']
    refs=movrefs(code,GLOBAL)
    L.append(f'- base `0x{GLOBAL:08X}` refs `{[(hex(x),hex(y),r) for x,y,r in refs]}`')
    gfuncs=sorted(set(fstart(d,x) for x,_,_ in refs))
    for fs in gfuncs:
        L+=['',f'### global-ref function `0x{fs:08X}` callers `{[hex(x) for x in callers(code,fs)]}`','```asm']
        # only show neighborhood around refs in this function
        rr=[x for x,_,_ in refs if fstart(d,x)==fs]
        lo=max(fs,min(rr)-0x40);hi=max(rr)+0x100
        L += [fmt(i) for i in dis(md,d,lo,hi)]+['```']

    # one complete pass over A32 code for field immediates/displacements
    hits=[]
    for ins in md.disasm(code,START):
        found=set()
        for op in ins.operands:
            if op.type==ARM_OP_MEM and abs(op.mem.disp) in FIELDS:found.add(abs(op.mem.disp))
            elif op.type==ARM_OP_IMM and abs(op.imm) in FIELDS:found.add(abs(op.imm))
        for f in found:hits.append((ins.address,f,fmt(ins)))
    L+=['','## Frame-field immediate/displacement census','']
    by=defaultdict(list)
    for addr,f,text in hits:by[fstart(d,addr)].append((addr,f,text))
    for fs,rows in sorted(by.items()):
        L+=['',f'### function `0x{fs:08X}` callers `{[hex(x) for x in callers(code,fs)]}`']
        for addr,f,text in rows:L.append(f'- `{FIELDS[f]}`: `{text}`')
        # neighborhoods around each hit, de-duped ranges
        shown=set()
        for addr,f,text in rows:
            bucket=addr&~0x7f
            if bucket in shown:continue
            shown.add(bucket);L+=['```asm']+[fmt(i) for i in dis(md,d,max(fs,addr-0x48),addr+0x70)]+['```']

    for t,name,span in ((0x016CDE50,'upstream CM/AAA containing function',0x1300),(0x016F2108,'ColorSpec top-level orchestration',0x650),(0x016F2C84,'ColorSpec entry wrapper',0x100)):
        L+=['',f'## {name} `0x{t:08X}`',f'- callers `{[hex(x) for x in callers(code,t)]}`','```asm']
        L += [fmt(i) for i in dis(md,d,t,t+span)]+['```']

    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
