#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
GLOBAL_BASE=0x43379A34
SRO_SLOT=0x10
TARGET_FUNCS=(0x0178C174,0x0178D8AC,0x0178E430,0x0178AC68,0x0178AD70,0x0178ADC4)

def is_push_lr(w): return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0

def prologue(code,addr,window=0x6000):
    q=addr-START
    for p in range(q-(q%4),max(-1,q-window),-4):
        if p>=0 and p+4<=len(code) and is_push_lr(struct.unpack_from('<I',code,p)[0]): return START+p
    return max(START,addr-0x400)

def decode_mov16(w,which):
    tag=w&0x0ff00000; want=0x03000000 if which=='movw' else 0x03400000
    if tag!=want:return None
    return (w>>12)&0xf,(((w>>4)&0xf000)|(w&0xfff))

def refs_to(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        m=decode_mov16(struct.unpack_from('<I',code,q)[0],'movw')
        if not m:continue
        rd,lo=m
        for r in range(q+4,min(q+32,len(code)-3),4):
            mt=decode_mov16(struct.unpack_from('<I',code,r)[0],'movt')
            if mt and mt[0]==rd:
                if ((mt[1]<<16)|lo)==target:out.append((START+q,START+r,rd))
                break
    return out

def sx(v,bits):
    s=1<<(bits-1);return (v^s)-s

def branch_target(addr,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (addr+8+sx(w&0xffffff,24)*4)&0xffffffff

def callers(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        w=struct.unpack_from('<I',code,q)[0]; a=START+q
        if branch_target(a,w)==target:out.append(a)
    return out

def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3)
    return list(md.disasm(code[lo-START:hi-START],lo))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    whole=a.unpacked.read_bytes();h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=whole[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    refs=refs_to(code,GLOBAL_BASE)
    L=['# M11-P SRO runtime-slot trace','',f'- SHA: `{h}`',f'- image-parameter global base: `0x{GLOBAL_BASE:08X}`',f'- SRO pointer slot: `+0x{SRO_SLOT:X}` -> `0x{GLOBAL_BASE+SRO_SLOT:08X}`',f'- base materializations: `{len(refs)}`','']
    slot_funcs={}
    for lo,hi,rd in refs:
        ins=dis(md,code,lo-0x60,hi+0x160)
        hits=[]
        for x in ins:
            if x.id==0: continue
            for op in x.operands:
                if op.type==ARM_OP_MEM and op.mem.base==rd and op.mem.disp==SRO_SLOT:
                    hits.append(x)
        if not hits:continue
        e=prologue(code,lo);slot_funcs.setdefault(e,[]).append((lo,hi,rd,hits,ins))
    L += [f'- functions accessing base+0x10 near materialization: `{len(slot_funcs)}`','']
    for e,rows in sorted(slot_funcs.items()):
        L += [f'## slot-access function `0x{e:08X}`','']
        for lo,hi,rd,hits,ins in rows:
            L += [f'- base ref: `0x{lo:08X}` via r{rd}',f'- slot ops: `{[fmt(x) for x in hits]}`','```asm']+[fmt(x) for x in ins]+['```','']
        cs=callers(code,e)
        L += [f'- direct BL callers: `{[hex(x) for x in cs]}`','']
        for c in cs[:20]:
            ce=prologue(code,c);ci=dis(md,code,max(ce,c-0x80),c+0x80)
            L += [f'### caller `0x{c:08X}` / function `0x{ce:08X}`','```asm']+[fmt(x) for x in ci]+['```','']
    L += ['## Known parameter-manager helper callers','']
    for f in TARGET_FUNCS:
        cs=callers(code,f)
        L += [f'- `0x{f:08X}` callers: `{[hex(x) for x in cs]}`']
    L += ['','## Interpretation boundary','',
          'The global +0x10 field is treated only as an SRO pointer candidate because the SRO write/delete wrapper explicitly frees it before mutating img/data/sro.bin. A runtime consumer requires a read of that slot followed by dataflow into image processing, not merely parameter I/O.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
