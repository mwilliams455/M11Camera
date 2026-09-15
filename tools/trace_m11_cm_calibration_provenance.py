#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,re,struct
from pathlib import Path
from collections import defaultdict
from functools import lru_cache
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000;END=0x02000000;DELTA=0x3FAA87D0
ROOT=0x43430188;CAL=0x43430258;COLOR=0x002C9A98
STRS={
  'Get_BinFileData':0x42223ED8,
  'Get_BinFileTfRemappingData':0x42223EF0,
  'config_fill':0x42223F14,
  'default_loaded':0x42223E8C,
  'binFileData':0x42223DD8,
}

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b): s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def decmov(w,kind):
    tag=w&0x0ff00000;want=0x03000000 if kind=='w' else 0x03400000
    if tag!=want:return None
    return (w>>12)&15,(((w>>4)&0xf000)|(w&0xfff))
def movrefs(d,lo,hi,target):
    out=[]
    for a in range(lo,hi-4,4):
        m=decmov(u32(d,a),'w')
        if not m:continue
        rd,l=m
        for b in range(a+4,min(a+40,hi-3),4):
            t=decmov(u32(d,b),'t')
            if t and t[0]==rd:
                if ((t[1]<<16)|l)==target:out.append((a,b,rd))
                break
    return out
def asc(d,a,n=240):
    if not(0<=a<len(d)):return None
    m=re.match(rb'[\x20-\x7e]{4,}\x00',d[a:a+n])
    return m.group()[:-1].decode('ascii','replace') if m else None
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def strings(d,lo,hi):
    for m in re.finditer(rb'[\x20-\x7e]{4,}\x00',d[lo:hi]):yield lo+m.start(),m.group()[:-1].decode('ascii','replace')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    @lru_cache(maxsize=None)
    def fs(x,win=0x18000):
        for p in range(x&~3,max(START,(x&~3)-win),-4):
            if push(u32(d,p)):return p
        return x&~3
    callmap=defaultdict(list)
    for x in range(START,END,4):
        t=bt(x,u32(d,x))
        if t is not None:callmap[t].append(x)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    def ann(lo,hi):
        ins=list(md.disasm(d[lo:hi],lo));pend={};out=[]
        for i in ins:
            note='';w=u32(d,i.address);mw=decmov(w,'w') if w is not None else None;mt=decmov(w,'t') if w is not None else None
            if mw:pend[mw[0]]=(mw[1],i.address)
            elif mt and mt[0] in pend:
                l,_=pend[mt[0]];v=(mt[1]<<16)|l
                s=asc(d,(v-DELTA)&0xffffffff) or asc(d,v)
                if s:note=f' ; ptr=0x{v:08X} "{s}"'
                elif v in (ROOT,CAL,COLOR):note=f' ; TARGET 0x{v:08X}'
            out.append(fmt(i)+note)
        return out
    L=['# M11 CM calibration provenance','',f'- SHA256 `{h}`',f'- root `0x{ROOT:08X}` calibration `0x{CAL:08X}` COLOR132 `0x{COLOR:08X}`','']
    L+=['## Nearby CM strings','']
    for p,s in strings(d,0x0277B300,0x0277B790):L.append(f'- file `0x{p:08X}` runtime `0x{p+DELTA:08X}` `{s}`')
    targets=[ROOT,CAL,COLOR,COLOR+0x2c,COLOR+0x58,(COLOR+DELTA)&0xffffffff]
    L+=['','## Direct MOVW/MOVT references','']
    allfunc=set()
    for t in targets:
        rr=movrefs(d,START,END,t);L.append(f'- `0x{t:08X}` refs `{[(hex(x),hex(y),r) for x,y,r in rr]}`')
        allfunc.update(fs(x) for x,_,_ in rr)
    for name,t in STRS.items():
        rr=movrefs(d,START,END,t);L.append(f'- string {name} `0x{t:08X}` refs `{[(hex(x),hex(y),r) for x,y,r in rr]}`')
        allfunc.update(fs(x) for x,_,_ in rr)
    L+=['','## Referencing functions','']
    for f in sorted(allfunc):
        refs=[]
        for t in list(targets)+list(STRS.values()):
            for x,y,r in movrefs(d,f,min(END,f+0x3000),t): refs.append((t,x,y,r))
        end=max([y for _,_,y,_ in refs]+[f])+0x240
        L += [f'### function `0x{f:08X}` direct callers `{[hex(x) for x in callmap.get(f,[])]}` refs `{[(hex(t),hex(x)) for t,x,_,_ in refs]}`','```asm']+ann(f,min(END,end))+['```','']
    # Search raw COLOR132 signatures and 44-byte copy geometry references near CM code.
    L+=['## COLOR132 signature occurrences','']
    vals=[2358,-546,-66,-2488,6300,1785,-403,797,3504,12,2850]
    sig=b''.join(struct.pack('<i',x) for x in vals);p=0;occ=[]
    while True:
        p=d.find(sig,p)
        if p<0:break
        occ.append(p);p+=1
    L.append(f'- full first record `{[hex(x) for x in occ]}`')
    # Exact literal pointers in full image, including data section.
    for t in targets:
        b=struct.pack('<I',t);pos=[];p=0
        while True:
            p=d.find(b,p)
            if p<0:break
            pos.append(p);p+=1
        L.append(f'- raw LE pointer `0x{t:08X}` occurs `{[hex(x) for x in pos[:200]]}`')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
