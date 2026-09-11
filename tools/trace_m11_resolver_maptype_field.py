#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
RESOLVER=0x0178C89C
SWITCH=0x0178C3D0
WRAPPER=0x0178D0A8


def sx(v,b):
    s=1<<(b-1); return (v^s)-s

def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff

def callers(code,t):
    return [START+q for q in range(0,len(code)-4,4) if bt(START+q,struct.unpack_from('<I',code,q)[0])==t]

def dis(md,code,lo,hi):
    lo=max(START,lo&~3); hi=min(END,(hi+3)&~3)
    return list(md.disasm(code[lo-START:hi-START],lo))

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def ispush(w): return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0

def pro(code,a,win=0x8000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(struct.unpack_from('<I',code,p)[0]): return START+p
    return max(START,a-0x400)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    whole=a.unpacked.read_bytes(); h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    code=whole[START:END]; md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True

    ins=dis(md,code,RESOLVER,RESOLVER+0x900)
    switch_calls=[]
    for x in ins:
        if x.address+4>END: continue
        q=x.address-START
        if 0<=q<=len(code)-4 and bt(x.address,struct.unpack_from('<I',code,q)[0])==SWITCH:
            switch_calls.append(x.address)

    L=['# M11-P resolver map-type field trace','',f'- SHA: `{h}`',f'- resolver: `0x{RESOLVER:08X}`',f'- map-type switch: `0x{SWITCH:08X}`',f'- switch calls inside bounded resolver window: `{[hex(x) for x in switch_calls]}`','', '## Resolver disassembly','```asm']+[fmt(x) for x in ins]+['```','']

    for c in switch_calls:
        win=dis(md,code,c-0x100,c+0x40)
        L += [f'## Dataflow window before switch call `0x{c:08X}`','```asm']+[fmt(x) for x in win]+['```','']
        # Report explicit loads/stores with memory displacements, useful for request-offset inference.
        for x in win:
            if x.id==0: continue
            mem=[]
            for op in x.operands:
                if op.type==ARM_OP_MEM:
                    mem.append((md.reg_name(op.mem.base),op.mem.disp))
            if mem: L += [f'- `{fmt(x)}` mem={mem}']
        L += ['']

    L += ['## Direct resolver callers','']
    for c in callers(code,RESOLVER):
        e=pro(code,c); ci=dis(md,code,max(e,c-0x160),c+0x80)
        L += [f'### `0x{c:08X}` / function `0x{e:08X}`','```asm']+[fmt(x) for x in ci]+['```','']

    L += ['## Wrapper callers','']
    for c in callers(code,WRAPPER):
        e=pro(code,c); ci=dis(md,code,max(e,c-0x120),c+0x60)
        L += [f'### `0x{c:08X}` / function `0x{e:08X}`','```asm']+[fmt(x) for x in ci]+['```','']

    L += ['## Decision boundary','',
          'The goal is to identify the request-structure field loaded into r0 immediately before the call to 0x0178C3D0. Once that offset is closed, scan request builders for value 5 at that exact field rather than inferring SRO use from generic helper arguments.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)

if __name__=='__main__': main()
