#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA
START=0x01000000; END=0x02000000
HELPERS=(0x0178C55C,0x0178C5F0,0x0178C670,0x0178C700,0x0178C7B4,0x0178C854,0x0178C89C)

def sx(v,b): s=1<<(b-1); return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):
    return [START+q for q in range(0,len(code)-4,4) if bt(START+q,struct.unpack_from('<I',code,q)[0])==t]
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x8000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(struct.unpack_from('<I',code,p)[0]):return START+p
    return max(START,a-0x400)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def r0const(ins,ca):
    prior=[x for x in ins if x.address<ca and x.id!=0]
    for x in reversed(prior[-24:]):
        if x.mnemonic in ('mov','movw') and len(x.operands)>=2 and x.operands[0].type==ARM_OP_REG and x.reg_name(x.operands[0].reg)=='r0' and x.operands[1].type==ARM_OP_IMM:return x.operands[1].imm&0xffffffff,fmt(x)
        try:
            _,wr=x.regs_access()
            if any(x.reg_name(r)=='r0' for r in wr):return None,fmt(x)
        except Exception:pass
    return None,None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    whole=a.unpacked.read_bytes();h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=whole[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P SRO index-5 caller trace','',f'- SHA: `{h}`','- SRO map type: `5`','']
    total5=0
    for helper in HELPERS:
        rows=[]
        for c in callers(code,helper):
            e=pro(code,c);ins=dis(md,code,max(e,c-0x100),c+0x50);v,why=r0const(ins,c);rows.append((c,e,v,why,ins))
        hist=Counter('unknown' if v is None else hex(v) for _,_,v,_,_ in rows)
        L += [f'## helper `0x{helper:08X}`',f'- callers: `{len(rows)}`',f'- r0 histogram: `{dict(hist)}`','']
        interesting=[r for r in rows if r[2] in (5,None)]
        total5 += sum(1 for r in rows if r[2]==5)
        for c,e,v,why,ins in interesting:
            L += [f'### call `0x{c:08X}` / function `0x{e:08X}`',f'- r0: `{None if v is None else hex(v)}`',f'- nearest r0 write: `{why}`','```asm']+[fmt(x) for x in ins]+['```','']
    L += ['## Summary','',f'- direct helper calls proven with r0=5: `{total5}`','',
          'Calls with unknown r0 remain unresolved because map type may arrive as a function argument or from a request structure. A proven r0=5 caller outside parameter-management code is a direct SRO-use lead.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
