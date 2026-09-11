#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000; DELTA=0x3FAA87D0
LOADER=0x0178AC68
KNOWN_CALLS=(0x0178C1B0,0x0178C288)

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):return [START+q for q in range(0,len(code)-4,4) if bt(START+q,u32(code,q))==t]
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def nextpro(code,a,lim=0x8000):
    q=a-START
    for p in range(q+4,min(len(code)-3,q+lim),4):
        if ispush(u32(code,p)):return START+p
    return min(END,a+lim)
def pro(code,a,win=0x10000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(u32(code,p)):return START+p
    return max(START,a-0x800)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def printable(d,p,n=240):
    if not 0<=p<len(d):return None
    e=d.find(b'\0',p,min(len(d),p+n))
    if e<0 or e-p<4:return None
    try:s=d[p:e].decode('ascii')
    except:return None
    return s if all((32<=ord(c)<127) or c in '\t\r\n' for c in s) else None
def strings(ins,d):
    out=[];seen=set()
    for i,x in enumerate(ins):
        if x.id==0 or x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM:continue
        rd=x.operands[0].reg;lo=x.operands[1].imm&0xffff
        for y in ins[i+1:i+10]:
            if y.id==0:continue
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==rd and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|lo
                for p,lab in (((v-DELTA)&0xffffffff,'affine'),(v,'raw')):
                    s=printable(d,p)
                    if s and (p,s) not in seen:seen.add((p,s));out.append((x.address,y.address,v,p,lab,s))
                break
    return out
def calls(ins,code):
    out=[]
    for x in ins:
        if x.id==0:continue
        q=x.address-START
        if 0<=q<=len(code)-4:
            t=bt(x.address,u32(code,q))
            if t is not None:out.append((x.address,t))
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    end=nextpro(code,LOADER);ins=dis(md,code,LOADER,end);cs=calls(ins,code)
    L=['# M11-P generic parameter file loader trace','',f'- SHA: `{h}`',f'- loader: `0x{LOADER:08X}..0x{end:08X}`',f'- direct callers: `{[hex(x) for x in callers(code,LOADER)]}`',f'- direct calls: `{[(hex(c),hex(t)) for c,t in cs]}`','',
       '## Known SRO tail-call ABI','',
       '- current SRO: `r0 = img/data/sro.bin`, `r1 = 0x43379A44`',
       '- default SRO: `r0 = img/data/default_sro.bin`, `r1 = 0x43379A50`','']
    ss=strings(ins,d)
    if ss:L += ['## Loader strings']+[f'- code `0x{x:08X}`/`0x{y:08X}` value `0x{v:08X}` -> {lab} `0x{p:08X}` `{s}`' for x,y,v,p,lab,s in ss]+['']
    L += ['## Loader body','```asm']+[fmt(x) for x in ins]+['```','']
    for c,t in cs:
        if not START<=t<END:continue
        ti=dis(md,code,t,min(END,t+0x300));tss=strings(ti,d)
        L += [f'## Callee `0x{t:08X}` from call `0x{c:08X}`',f'- whole-image callers: `{[hex(x) for x in callers(code,t)[:100]]}`']
        if tss:L += [f'- string: `{s}`' for _,_,_,_,_,s in tss]
        L += ['```asm']+[fmt(x) for x in ti]+['```','']
    # Show caller windows for all direct callers to infer generic ABI/use classes.
    L += ['## Direct caller windows','']
    for c in callers(code,LOADER):
        e=pro(code,c);ci=dis(md,code,max(e,c-0x70),c+0x50)
        L += [f'### call `0x{c:08X}` / function `0x{e:08X}`','```asm']+[fmt(x) for x in ci]+['```','']
    L += ['## Decision boundary','',
          'The loader ABI is closed only from explicit dataflow. For SRO, r1 is already proven to be the destination global slot address. The next requirement is to identify the allocated object format and whether the file bytes are copied verbatim, wrapped by a header, or parsed before publication. Only then can matrix-field offsets be searched safely.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
