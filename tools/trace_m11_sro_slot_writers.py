#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_OP_IMM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
BASE=0x43379A34
SLOTS={0x10:'current_sro',0x1C:'default_sro'}
DELTA_DATA=0x3EFD2A98
COLOR132=0x002C9A98

def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def decode_mov16(w,kind):
    tag=w&0x0ff00000; want=0x03000000 if kind=='movw' else 0x03400000
    if tag!=want:return None
    return (w>>12)&0xf,(((w>>4)&0xf000)|(w&0xfff))
def refs(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        m=decode_mov16(u32(code,q),'movw')
        if not m:continue
        rd,lo=m
        for p in range(q+4,min(q+36,len(code)-3),4):
            mt=decode_mov16(u32(code,p),'movt')
            if mt and mt[0]==rd:
                if ((mt[1]<<16)|lo)==target:out.append((START+q,START+p,rd))
                break
    return out
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x10000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(u32(code,p)):return START+p
    return max(START,a-0x800)
def nextpro(code,a,lim=0x3000):
    q=a-START
    for p in range(q+4,min(len(code)-3,q+lim),4):
        if ispush(u32(code,p)):return START+p
    return min(END,a+lim)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):return [START+q for q in range(0,len(code)-4,4) if bt(START+q,u32(code,q))==t]
def rname(rd):return 'sp' if rd==13 else 'lr' if rd==14 else 'pc' if rd==15 else f'r{rd}'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    base_refs=refs(code,BASE); funcs={}
    for lo,hi,rd in base_refs:
        e=pro(code,lo);end=nextpro(code,e);ins=dis(md,code,e,end);wanted=rname(rd);hits=[]
        for x in ins:
            if x.id==0:continue
            for op in x.operands:
                if op.type==ARM_OP_MEM and md.reg_name(op.mem.base)==wanted and op.mem.disp in SLOTS:
                    hits.append((x,op.mem.disp))
        if hits:funcs.setdefault(e,[]).append((lo,hi,rd,hits,ins))
    L=['# M11-P current/default SRO slot writer trace','',f'- SHA: `{h}`',f'- parameter base: `0x{BASE:08X}`',f'- current slot: `+0x10`',f'- default slot: `+0x1C`',f'- COLOR132 file offset: `0x{COLOR132:08X}`',f'- COLOR132 candidate DATA affine runtime: `0x{COLOR132+DELTA_DATA:08X}`','']
    for e,rows in sorted(funcs.items()):
        ops=[]
        for _,_,_,hits,_ in rows:
            for x,disp in hits:ops.append((x,disp))
        # Dedup by address/disp
        uniq=[];seen=set()
        for x,disp in ops:
            if (x.address,disp) not in seen:seen.add((x.address,disp));uniq.append((x,disp))
        if not any(x.mnemonic.startswith('str') for x,_ in uniq):continue
        end=nextpro(code,e);ins=dis(md,code,e,end)
        L += [f'## writer function `0x{e:08X}..0x{end:08X}`','']
        for x,disp in uniq:L += [f'- {SLOTS[disp]}: `{fmt(x)}`']
        L += [f'- direct callers: `{[hex(c) for c in callers(code,e)]}`','```asm']+[fmt(x) for x in ins]+['```','']
        for c in callers(code,e)[:30]:
            ce=pro(code,c);ci=dis(md,code,max(ce,c-0x120),c+0x100)
            L += [f'### caller `0x{c:08X}` / function `0x{ce:08X}`','```asm']+[fmt(x) for x in ci]+['```','']
    # Direct refs to the candidate affine pointer itself, and to the exact unaligned hit seen previously.
    for t,label in ((COLOR132+DELTA_DATA,'COLOR132 base'),(COLOR132+DELTA_DATA+0x1A,'COLOR132+0x1A')):
        rr=refs(code,t)
        lit=[]
        needle=struct.pack('<I',t&0xffffffff)
        p=0
        while True:
            p=d.find(needle,p)
            if p<0:break
            if p%4==0:lit.append(p)
            p+=1
        L += [f'## Pointer probe {label} `0x{t:08X}`',f'- MOVW/MOVT code refs: `{[(hex(x),hex(y),r) for x,y,r in rr]}`',f'- aligned exact-u32 whole-image occurrences: `{[hex(x) for x in lit[:100]]}`','']
    L += ['## Interpretation boundary','',
          'A default-slot write tied to a static payload is the required bridge between the embedded sro.bin-adjacent COLOR132 bytes and runtime SRO selection. The DPC/PDAF helper alone does not establish use of matrix fields; this trace only closes slot initialization when the store/dataflow is explicit.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
