#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
DATA_DELTA=0x3FAA87D0
PARAM_BASE=0x43379A34
TARGETS={
    0x0178C174:'current_sro_reload_hook',
    0x0178C24C:'default_sro_reload_hook',
}

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
def nextpro(code,a,lim=0x5000):
    q=a-START
    for p in range(q+4,min(len(code)-3,q+lim),4):
        if ispush(u32(code,p)):return START+p
    return min(END,a+lim)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3)
    return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def printable(d,p,n=240):
    if not 0<=p<len(d):return None
    e=d.find(b'\0',p,min(len(d),p+n))
    if e<0 or e-p<4:return None
    b=d[p:e]
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\t\r\n') or ord(c)>=127 for c in s):return None
    return s
def strings_from_movpairs(ins,d):
    out=[];seen=set()
    for i,x in enumerate(ins):
        if x.id==0 or x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM:continue
        rd=x.operands[0].reg;lo=x.operands[1].imm&0xffff
        for y in ins[i+1:i+10]:
            if y.id==0:continue
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==rd and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|lo
                for p,lab in (((v-DATA_DELTA)&0xffffffff,'affine'),(v,'raw')):
                    s=printable(d,p)
                    if s and (p,s) not in seen:
                        seen.add((p,s));out.append((x.address,y.address,v,p,lab,s))
                break
    return out
def bls(ins,code):
    out=[]
    for x in ins:
        if x.id==0:continue
        q=x.address-START
        if 0<=q<=len(code)-4:
            t=bt(x.address,u32(code,q))
            if t is not None:out.append((x.address,t))
    return out
def target_summary(md,code,d,t):
    if not START<=t<END:return [],[]
    ins=dis(md,code,t,min(END,t+0x240))
    return strings_from_movpairs(ins,d),bls(ins,code)
def slot_ops(md,ins):
    out=[]
    # Track direct construction of PARAM_BASE and one-step register aliases.
    bases={}
    for x in ins:
        if x.id==0:continue
        ops=x.operands
        if x.mnemonic=='movw' and len(ops)>=2 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_IMM:
            bases[md.reg_name(ops[0].reg)]=('low',ops[1].imm&0xffff)
        elif x.mnemonic=='movt' and len(ops)>=2 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_IMM:
            n=md.reg_name(ops[0].reg);prev=bases.get(n)
            if prev and prev[0]=='low':
                v=((ops[1].imm&0xffff)<<16)|prev[1]
                bases[n]=('const',v)
        elif x.mnemonic=='mov' and len(ops)>=2 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_REG:
            dst=md.reg_name(ops[0].reg);src=md.reg_name(ops[1].reg)
            if src in bases:bases[dst]=bases[src]
        for op in ops:
            if op.type==ARM_OP_MEM:
                b=md.reg_name(op.mem.base);st=bases.get(b)
                if st and st[0]=='const' and st[1]==PARAM_BASE and op.mem.disp in (0x10,0x1c):
                    out.append((x.address,op.mem.disp,fmt(x)))
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P SRO reload-path trace','',f'- SHA: `{h}`',f'- parameter base: `0x{PARAM_BASE:08X}`','']
    all_callees=set()
    for t,name in TARGETS.items():
        e=pro(code,t);end=nextpro(code,t);ins=dis(md,code,t,end);calls=bls(ins,code);all_callees|={x for _,x in calls}
        L += [f'## {name} `0x{t:08X}..0x{end:08X}`','',f'- direct callers: `{[hex(x) for x in callers(code,t)]}`',f'- slot ops: `{slot_ops(md,ins)}`',f'- direct calls: `{[(hex(c),hex(x)) for c,x in calls]}`','']
        ss=strings_from_movpairs(ins,d)
        if ss:L += ['### Referenced strings']+[f'- code `0x{x:08X}`/`0x{y:08X}` value `0x{v:08X}` -> {lab} file `0x{p:08X}` `{s}`' for x,y,v,p,lab,s in ss]+['']
        L += ['```asm']+[fmt(x) for x in ins]+['```','']
        for c in callers(code,t):
            ce=pro(code,c);ci=dis(md,code,max(ce,c-0x120),c+0x90)
            L += [f'### caller `0x{c:08X}` / function `0x{ce:08X}`','```asm']+[fmt(x) for x in ci]+['```','']
    L += ['## Callee identities / local evidence','']
    for t in sorted(all_callees):
        ss,calls=target_summary(md,code,d,t)
        L += [f'### callee `0x{t:08X}`',f'- callers in whole A32 image: `{[hex(x) for x in callers(code,t)[:80]]}`',f'- first-window calls: `{[(hex(c),hex(x)) for c,x in calls]}`']
        if ss:L += [f'- string: code `0x{x:08X}`/`0x{y:08X}` -> `{s}`' for x,y,v,p,lab,s in ss]
        ti=dis(md,code,t,min(END,t+0x180)) if START<=t<END else []
        if ti:L += ['```asm']+[fmt(x) for x in ti]+['```']
        L += ['']
    L += ['## Decision boundary','',
          'These hooks are accepted as SRO reload/load paths only where their own calls, strings and slot stores establish that role. A generic file-loader call does not by itself prove that COLOR132 matrix words are consumed. The next closure requires tracing the returned allocation/parser object into +0x10/+0x1C and then locating matrix-field readers.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
