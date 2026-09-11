#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
DELTA=0x3FAA87D0
SWITCH=0x0178C3D0
JTABLE=0x0178C3DC
COUNT=19
SRO_CASE=0x0178C488
HELPERS=(0x0178C55C,0x0178C5F0,0x0178C89C,0x0178D0A8)

def sx(v,bits):
    s=1<<(bits-1); return (v^s)-s

def branch_target(addr,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (addr+8+sx(w&0xffffff,24)*4)&0xffffffff

def callers(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        w=struct.unpack_from('<I',code,q)[0]; a=START+q
        if branch_target(a,w)==target: out.append(a)
    return out

def is_push_lr(w): return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0

def prologue(code,addr,window=0x8000):
    q=addr-START
    for p in range(q-(q%4),max(-1,q-window),-4):
        if p>=0 and p+4<=len(code) and is_push_lr(struct.unpack_from('<I',code,p)[0]):return START+p
    return max(START,addr-0x400)

def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3)
    return list(md.disasm(code[lo-START:hi-START],lo))

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def infer_r0_const(ins,call_addr):
    prior=[x for x in ins if x.address<call_addr and x.id!=0]
    for x in reversed(prior[-18:]):
        if not x.operands: continue
        # Any write to r0 terminates backward search; accept simple MOV/MOVW immediate.
        writes_r0=False
        try:
            _,wr=x.regs_access(); writes_r0=any(x.reg_name(r)=='r0' for r in wr)
        except Exception:
            pass
        if x.mnemonic in ('mov','movw') and len(x.operands)>=2 and x.operands[0].type==ARM_OP_REG and x.reg_name(x.operands[0].reg)=='r0' and x.operands[1].type==ARM_OP_IMM:
            return x.operands[1].imm & 0xffffffff,fmt(x)
        if writes_r0:return None,fmt(x)
    return None,None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    whole=a.unpacked.read_bytes();h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=whole[START:END]; md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    entries=[]
    for i in range(COUNT):
        off=JTABLE-START+i*4
        word=struct.unpack_from('<I',code,off)[0]
        target=(word-DELTA)&0xffffffff
        entries.append((i,word,target))
    sro_indices=[i for i,w,t in entries if t==SRO_CASE]
    L=['# M11-P SRO parameter-switch consumer trace','',f'- SHA: `{h}`',f'- switch: `0x{SWITCH:08X}`',f'- jump table: `0x{JTABLE:08X}` × {COUNT}',f'- SRO getter case target: `0x{SRO_CASE:08X}`',f'- SRO switch indices: `{sro_indices}`','', '## Jump table','']
    for i,w,t in entries:L += [f'- index {i:2d}: runtime `0x{w:08X}` -> code `0x{t:08X}`'+(' **SRO**' if t==SRO_CASE else '')]
    L += ['','## Direct callers','']
    for target in (SWITCH,SRO_CASE)+HELPERS:
        cs=callers(code,target)
        L += [f'### target `0x{target:08X}`',f'- direct BL callers: `{[hex(x) for x in cs]}`','']
        for c in cs:
            e=prologue(code,c);ins=dis(md,code,max(e,c-0x100),c+0x70);v,why=infer_r0_const(ins,c)
            L += [f'#### call `0x{c:08X}` / function `0x{e:08X}`',f'- inferred r0 constant: `{None if v is None else hex(v)}`',f'- nearest r0 write: `{why}`','```asm']+[fmt(x) for x in ins]+['```','']
    L += ['## Interpretation boundary','',
          'The switch index establishes the map-type ID that selects current/default SRO. A production SRO consumer is only closed when a non-parameter-management call reaches that index (directly or through a helper) and the returned SRO pointer is then consumed by image-processing code.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
