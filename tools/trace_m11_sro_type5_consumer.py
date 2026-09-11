#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
DELTA=0x3FAA87D0
FUNC=0x0175DE14
FUNC_END=0x0175E4FC
RESOLVE_CALL=0x0175DFC4
RESOLVER_WRAPPER=0x0178D0A8


def sx(v,b): s=1<<(b-1); return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):
    return [START+q for q in range(0,len(code)-4,4) if bt(START+q,struct.unpack_from('<I',code,q)[0])==t]
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x10000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(struct.unpack_from('<I',code,p)[0]):return START+p
    return max(START,a-0x800)
def ascii_at(whole,p,n=220):
    if not 0<=p<len(whole):return None
    out=[]
    for b in whole[p:p+n]:
        if b==0:break
        if b in (9,10,13) or 32<=b<127:out.append(chr(b))
        else:return None
    s=''.join(out).strip();return s if len(s)>=5 else None
def nearby_strings(ins,whole):
    rows=[];seen=set()
    for i,x in enumerate(ins):
        if x.id==0 or x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM:continue
        reg=x.operands[0].reg;lo=x.operands[1].imm&0xffff
        for y in ins[i+1:i+9]:
            if y.id==0:continue
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|lo
                for p,lab in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(whole,p)
                    if s and (p,s) not in seen:seen.add((p,s));rows.append((p,lab,s))
                break
    return rows

def bl_targets(ins,code):
    out=[]
    for x in ins:
        q=x.address-START
        if x.id==0 or q<0 or q+4>len(code):continue
        t=bt(x.address,struct.unpack_from('<I',code,q)[0])
        if t is not None:out.append((x.address,t))
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    whole=a.unpacked.read_bytes();h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=whole[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    ins=dis(md,code,FUNC,FUNC_END)
    L=['# M11-P proven SRO type-5 consumer trace','',f'- SHA: `{h}`',f'- function: `0x{FUNC:08X}..0x{FUNC_END:08X}`',f'- proven type-5 resolve call: `0x{RESOLVE_CALL:08X}`','', '## Full function','```asm']+[fmt(x) for x in ins]+['```','']
    ss=nearby_strings(ins,whole)
    L += ['## Strings referenced by function','']+[f'- {lab} `0x{p:08X}`: `{s[:210]}`' for p,lab,s in ss]+['']
    calls=bl_targets(ins,code)
    L += ['## Direct call targets','']+[f'- call `0x{c:08X}` -> `0x{t:08X}`' for c,t in calls]+['']
    # Inspect every non-logging/non-memset target around its entry for assertion/name strings.
    for c,t in calls:
        if not (START<=t<END):continue
        ti=dis(md,code,t,t+0x180)
        tss=nearby_strings(ti,whole)
        if tss:
            L += [f'### target `0x{t:08X}` from `0x{c:08X}` strings']+[f'- {lab} `0x{p:08X}`: `{s[:180]}`' for p,lab,s in tss]+['']
    L += ['## Direct callers of SRO consumer','']
    for c in callers(code,FUNC):
        e=pro(code,c);ci=dis(md,code,max(e,c-0x180),c+0x100);css=nearby_strings(ci,whole)
        L += [f'### caller `0x{c:08X}` / function `0x{e:08X}`','```asm']+[fmt(x) for x in ci]+['```']
        if css:L += ['strings:']+[f'- {lab} `0x{p:08X}`: `{s[:190]}`' for p,lab,s in css]
        L += ['']
    # Post-resolve: list all loads/stores and calls after the returned pointer is saved to fp-0x0c.
    post=[x for x in ins if x.address>=RESOLVE_CALL and x.address<FUNC_END]
    L += ['## Post-resolve memory/call operations','']
    for x in post:
        if x.id==0:continue
        mem=[]
        for op in x.operands:
            if op.type==ARM_OP_MEM:mem.append((md.reg_name(op.mem.base),op.mem.disp))
        q=x.address-START;t=None
        if 0<=q<=len(code)-4:t=bt(x.address,struct.unpack_from('<I',code,q)[0])
        if mem or t is not None:L += [f'- `{fmt(x)}` mem={mem}'+(f' BL->0x{t:08X}' if t is not None else '')]
    L += ['','## Decision boundary','',
          'This function is a proven SRO map-type-5 resolver consumer. The third Q9 record may be promoted into the rendering model only if post-resolve dataflow shows the returned SRO payload selecting/reading the third 44-byte record (or an equivalent derived transform) on the still-photo path.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
