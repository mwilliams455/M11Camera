#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000; DELTA=0x3FAA87D0
COLOR132=0x002C9A98
SELECTOR=0x0178C55C
SWITCH=0x0178C3D0
NAMES=(b'img/data/sro.bin\x00',b'img/data/default_sro.bin\x00',b'img/data/R2Y_CC0_CM.bin\x00',b'img/data/r2y.bin\x00')

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):return [START+q for q in range(0,len(code)-4,4) if bt(START+q,u32(code,q))==t]
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x10000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(u32(code,p)):return START+p
    return max(START,a-0x800)
def nextpro(code,a,lim=0x4000):
    q=a-START
    for p in range(q+4,min(len(code)-3,q+lim),4):
        if ispush(u32(code,p)):return START+p
    return min(END,a+lim)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def allhits(d,n):
    out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:return out
        out.append(p);p+=1
def ascii_imgdata(d,lo,hi):
    out=[];p=max(0,lo)
    while True:
        p=d.find(b'img/data/',p,min(len(d),hi))
        if p<0:return out
        e=d.find(b'\x00',p,min(len(d),p+160))
        if e<0:return out
        try:s=d[p:e].decode('ascii')
        except: p+=1;continue
        out.append((p,e+1,s));p=e+1
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
                    if 0<=p<len(d):
                        e=d.find(b'\0',p,min(len(d),p+220))
                        if e>p+3:
                            try:s=d[p:e].decode('ascii')
                            except:s=''
                            if s and all(32<=ord(c)<127 for c in s) and (p,s) not in seen:
                                seen.add((p,s));out.append((x.address,y.address,v,p,lab,s))
                break
    return out

def infer_r0_before(ins,call_addr,md):
    prior=[x for x in ins if x.address<call_addr and x.id!=0]
    for x in reversed(prior[-25:]):
        ops=x.operands
        if x.mnemonic in ('mov','movw') and len(ops)>=2 and ops[0].type==ARM_OP_REG and md.reg_name(ops[0].reg)=='r0' and ops[1].type==ARM_OP_IMM:
            return ops[1].imm&0xffffffff,fmt(x)
        try:
            _,wr=x.regs_access()
            if any(md.reg_name(r)=='r0' for r in wr):return None,fmt(x)
        except:pass
    return None,None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P SRO static catalog + selector trace','',f'- SHA: `{h}`',f'- COLOR132: `0x{COLOR132:08X}`','']
    L += ['## Named resource occurrences','']
    for n in NAMES:
        L += [f'- `{n[:-1].decode()}`: `{[hex(x) for x in allhits(d,n)]}`']
    L += ['','## img/data catalog neighborhood','']
    ents=ascii_imgdata(d,COLOR132-0x1000,COLOR132+0x2000)
    for idx,(p,e,s) in enumerate(ents):
        nxt=ents[idx+1][0] if idx+1<len(ents) else None
        L += [f'### `{s}` @ `0x{p:08X}`',f'- string end+NUL: `0x{e:08X}`',f'- next img/data name: `{None if nxt is None else hex(nxt)}`',f'- span to next name: `{None if nxt is None else hex(nxt-p)}`']
        # common aligned starts after name
        for al in (4,8,16,32):
            q=(e+al-1)&~(al-1)
            L += [f'- align{al} after name: `0x{q:08X}`, bytes-to-next=`{None if nxt is None else nxt-q}`']
        if nxt is not None:
            q=(e+15)&~15
            L += [f'- first 48 bytes from align16: `{d[q:min(nxt,q+48)].hex()}`']
    L += ['','## SRO exact framing checks','']
    sroh=allhits(d,NAMES[0])
    cc0h=allhits(d,NAMES[2])
    if sroh:
        sp=sroh[0];se=sp+len(NAMES[0]);aligned=(se+15)&~15
        L += [f'- sro name: `0x{sp:08X}`..`0x{se:08X}`',f'- align16 payload candidate: `0x{aligned:08X}`',f'- COLOR132 delta from aligned: `{COLOR132-aligned}`']
    if cc0h:
        L += [f'- next R2Y_CC0 name: `0x{cc0h[0]:08X}`',f'- bytes COLOR132 -> next name: `{cc0h[0]-COLOR132}` (`0x{cc0h[0]-COLOR132:X}`)']
        L += [f'- exact COLOR132[132] ends at: `0x{COLOR132+132:08X}`',f'- end equals next name: `{COLOR132+132==cc0h[0]}`']
    L += ['','## Selector 0x0178C55C','']
    end=nextpro(code,SELECTOR);ins=dis(md,code,SELECTOR,end)
    L += [f'- function: `0x{SELECTOR:08X}..0x{end:08X}`',f'- direct callers: `{[hex(x) for x in callers(code,SELECTOR)]}`']
    ss=strings(ins,d)
    if ss:L += [f'- string `{s}` via `0x{x:08X}`' for x,y,v,p,lab,s in ss]
    L += ['```asm']+[fmt(x) for x in ins]+['```','']
    L += ['## Selector direct callers and r0 constants','']
    for c in callers(code,SELECTOR):
        e=pro(code,c);ci=dis(md,code,max(e,c-0x180),c+0x80);v,why=infer_r0_before(ci,c,md)
        L += [f'### call `0x{c:08X}` / function `0x{e:08X}`',f'- inferred r0 before call: `{None if v is None else hex(v)}` via `{why}`','```asm']+[fmt(x) for x in ci]+['```','']
    # Who calls generic switch directly, for comparison.
    L += ['## Generic switch direct callers','']
    for c in callers(code,SWITCH):
        e=pro(code,c);ci=dis(md,code,max(e,c-0x90),c+0x40);v,why=infer_r0_before(ci,c,md)
        L += [f'- call `0x{c:08X}` func `0x{e:08X}` r0=`{None if v is None else hex(v)}` via `{why}`']
    L += ['','## Interpretation boundary','',
          'Static file framing is accepted only if the catalog boundary is exact and consistent with neighboring entries; selector semantics are accepted only from its actual loads/stride/arithmetic. A read at an offset numerically inside COLOR132 is not enough by itself to prove a colour transform.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
