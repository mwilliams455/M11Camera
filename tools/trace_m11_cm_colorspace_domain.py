#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,re,struct
from pathlib import Path
from collections import defaultdict
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000;END=0x02000000;DELTA=0x3FAA87D0
TABLE_RT=0x42225208; TABLE_FILE=(TABLE_RT-DELTA)&0xffffffff
ROOT=0x43430188

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def f64(d,a): return struct.unpack_from('<d',d,a)[0] if 0<=a<=len(d)-8 else None
def sx(v,b): s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def asc(d,a,n=240):
    if not (0<=a<len(d)):return None
    m=re.match(rb'[\x20-\x7e]{4,}\x00',d[a:a+n]);return m.group()[:-1].decode('ascii','replace') if m else None
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def rt2file(v):
    x=(v-DELTA)&0xffffffff
    return x if 0<=x<0x04000000 else None
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11 CM colorspace/domain trace','',f'- SHA256 `{h}`',f'- selector table runtime `0x{TABLE_RT:08X}`, file `0x{TABLE_FILE:08X}`','']
    L+=['## Selector table raw entries (12-byte stride)','']
    entries=[]; ptrs=[]
    for i in range(3):
        a0=TABLE_FILE+i*12; vals=[u32(d,a0+j) for j in (0,4,8)]; entries.append(vals)
        pretty=[]
        for v in vals:
            fp=rt2file(v) if v is not None else None
            s=asc(d,fp) if fp is not None else None
            pretty.append(f'0x{v:08X}'+(f' -> file 0x{fp:08X}' if fp is not None else '')+(f' "{s}"' if s else ''))
        L.append(f'- entry {i}: `{pretty}`')
        for v in vals[1:]:
            fp=rt2file(v)
            if fp is not None and START<=fp<END:ptrs.append(fp)
    L+=['','## Selector helper functions and returned matrices','']
    matrix_ptrs=[]
    for p in sorted(set(ptrs)):
        ins=list(md.disasm(d[p:p+0x20],p))
        L += [f'### helper file `0x{p:08X}` runtime `0x{p+DELTA:08X}`','```asm']+[fmt(x) for x in ins]+['```']
        # helpers are tiny MOVW/MOVT pointer-return stubs; reconstruct target from the immediates.
        lo=hi=None
        for x in ins:
            if x.mnemonic=='movw' and x.op_str.startswith('r3, #'):
                lo=int(x.op_str.split('#')[1],0)
            if x.mnemonic=='movt' and x.op_str.startswith('r3, #'):
                hi=int(x.op_str.split('#')[1],0)
        if lo is not None and hi is not None:
            rt=(hi<<16)|lo; fp=rt2file(rt); matrix_ptrs.append((p,rt,fp))
            L.append(f'- returns runtime `0x{rt:08X}` -> file `0x{fp:08X}`')
            vals=[f64(d,fp+8*j) for j in range(9)]
            L.append('- 3x3 doubles:')
            for r in range(3): L.append('  - `['+', '.join(f'{vals[3*r+c]:.12f}' for c in range(3))+']`')
        L.append('')
    L+=['## Entry pairing','']
    for i,vals in enumerate(entries):
        helper_files=[rt2file(vals[1]),rt2file(vals[2])]
        ret=[]
        for hf in helper_files:
            row=next((x for x in matrix_ptrs if x[0]==hf),None)
            ret.append(None if row is None else row[1])
        L.append(f'- selector {i}: helpers `{[hex(x) for x in helper_files]}` matrices `{[None if x is None else hex(x) for x in ret]}`')
    L+=['','## Color-space setup in cm_fill_parameter','```asm']
    L += [fmt(x) for x in md.disasm(d[0x016EBFF0:0x016EC0B8],0x016EBFF0)]+['```','']
    L+=['## ColorSpec main output tail','```asm']
    L += [fmt(x) for x in md.disasm(d[0x016F2780:0x016F2CA0],0x016F2780)]+['```','']
    callmap=defaultdict(list)
    for q in range(START,END,4):
        t=bt(q,u32(d,q))
        if t is not None:callmap[t].append(q)
    L+=['## Selected direct call relationships','']
    for t in [0x016F1CB8,0x016F1FB4,0x016F2C84,0x016EB09C,0x016EB010]:
        L.append(f'- target `0x{t:08X}` callers `{[hex(x) for x in callmap.get(t,[])]}`')
    L+=['','## Nearby table strings','']
    for lo,hi in [(max(0,TABLE_FILE-0x600),min(len(d),TABLE_FILE+0x600)),(0x0277BC40,0x0277C300)]:
        for m in re.finditer(rb'[\x20-\x7e]{4,}\x00',d[lo:hi]):
            p=lo+m.start();s=m.group()[:-1].decode('ascii','replace');L.append(f'- file `0x{p:08X}` runtime `0x{p+DELTA:08X}` `{s}`')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
