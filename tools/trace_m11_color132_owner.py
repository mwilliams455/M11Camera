#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

CODE_START=0x01000000
CODE_END=0x02000000
OBJ=0x002C9A98
RECORDS=(OBJ,OBJ+0x2C,OBJ+0x58)
# Two independently encountered static-data affines in the Leica image.
DELTAS=(0x3FAA87D0,0x3EFD2A98)

def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def ispush(w): return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x8000):
    q=a-CODE_START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(u32(code,p)): return CODE_START+p
    return max(CODE_START,a-0x400)
def decode_mov16(w,kind):
    tag=w&0x0ff00000; want=0x03000000 if kind=='movw' else 0x03400000
    if tag!=want:return None
    return (w>>12)&0xf,(((w>>4)&0xf000)|(w&0xfff))
def movrefs(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        m=decode_mov16(u32(code,q),'movw')
        if not m:continue
        rd,lo=m
        for r in range(q+4,min(q+36,len(code)-3),4):
            mt=decode_mov16(u32(code,r),'movt')
            if mt and mt[0]==rd:
                if ((mt[1]<<16)|lo)==target:out.append((CODE_START+q,CODE_START+r,rd))
                break
    return out
def alloccs(data,needle):
    out=[];p=0
    while True:
        p=data.find(needle,p)
        if p<0:return out
        out.append(p);p+=1
def printable_at(d,p,n=220):
    if not 0<=p<len(d):return None
    e=d.find(b'\0',p,min(len(d),p+n))
    if e<0 or e-p<4:return None
    b=d[p:e]
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\t\r\n') or ord(c)>=127 for c in s):return None
    return s
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def dis(md,code,lo,hi):
    lo=max(CODE_START,lo&~3);hi=min(CODE_END,(hi+3)&~3)
    return list(md.disasm(code[lo-CODE_START:hi-CODE_START],lo))
def strings_near(d,lo,hi):
    out=[];p=max(0,lo)
    while p<min(len(d),hi):
        if 32<=d[p]<127 and (p==0 or not 32<=d[p-1]<127):
            s=printable_at(d,p)
            if s:out.append((p,s));p+=max(1,len(s))
        p+=1
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[CODE_START:CODE_END]
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P neutral COLOR132 owner / xref trace','',f'- SHA: `{h}`',f'- object file offset: `0x{OBJ:08X}`',f'- record file offsets: `{[hex(x) for x in RECORDS]}`','']
    words=list(struct.unpack_from('<33i',d,OBJ))
    L += ['## Exact 33-word object',f'- words: `{words}`','']
    L += ['## Local surroundings','']
    for off in range(OBJ-0x80,OBJ+132+0x80,4):
        if 0<=off<=len(d)-4:L.append(f'- `0x{off:08X}`: `0x{u32(d,off):08X}` ({struct.unpack_from("<i",d,off)[0]})')
    ss=strings_near(d,OBJ-0x2000,OBJ+0x2000)
    L += ['','## Printable strings within ±0x2000','']+[f'- `0x{p:08X}`: `{s[:200]}`' for p,s in ss]+['']

    for delta in DELTAS:
        L += [f'## Candidate affine `+0x{delta:08X}`','']
        for ro in RECORDS:
            t=(ro+delta)&0xffffffff
            mr=movrefs(code,t)
            lits=[p for p in alloccs(code,struct.pack('<I',t)) if p%4==0]
            whole=[p for p in alloccs(d,struct.pack('<I',t)) if p%4==0]
            L += [f'### file `0x{ro:08X}` -> runtime `0x{t:08X}`',f'- MOVW/MOVT refs: `{[(hex(x),hex(y),r) for x,y,r in mr]}`',f'- aligned literal refs in code: `{[hex(CODE_START+p) for p in lits[:100]]}`',f'- aligned exact-u32 occurrences whole image: `{[hex(p) for p in whole[:100]]}`','']
            refs=[x for pair in mr for x in pair[:1]]+[CODE_START+p for p in lits]
            seen=set()
            for r in refs[:40]:
                e=pro(code,r)
                key=(e,r)
                if key in seen:continue
                seen.add(key)
                ins=dis(md,code,max(e,r-0x100),r+0x180)
                L += [f'#### xref `0x{r:08X}` / function `0x{e:08X}`','```asm']+[fmt(i) for i in ins]+['```','']

    # Scan candidate pointers into any byte of the 132-byte object under each affine.
    L += ['## Whole-image pointers into object range','']
    for delta in DELTAS:
        lo=(OBJ+delta)&0xffffffff; hi=(OBJ+132+delta)&0xffffffff
        hits=[]
        for p in range(0,len(d)-3,4):
            v=u32(d,p)
            if lo<=v<hi:hits.append((p,v,v-lo))
        L += [f'- delta `0x{delta:08X}` pointer-range hits `{len(hits)}`: `{[(hex(p),hex(v),hex(o)) for p,v,o in hits[:200]]}`']
    L += ['','## Interpretation boundary','',
          'The 132-byte structure is treated as a neutral COLOR132 object. A candidate affine is accepted only where actual code/data xrefs support it. Presence of exact DNG matrices proves object content, not runtime colour placement. Renderer promotion requires a production consumer and record-selection/scale semantics.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
