#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000
END=0x02000000
AAA_FUNC=0x016CDE50
WRAPPER=0x016DCE0C
PRODUCER=0x016DCEB0
AWB_REFRESH=0x016DF908
SRC_BASE=0x4342F91C
SRC_OFFS={0x4D8,0x4DC,0x4E0,0x4E4}
DELTA=0x3FAA87D0

def sx(v,bits):
    sign=1<<(bits-1); return (v^sign)-sign

def branch_target(addr,w):
    if ((w>>25)&0x7)!=0x5 or ((w>>24)&1)!=1: return None
    return (addr+8 + sx(w&0xFFFFFF,24)*4) & 0xFFFFFFFF

def str_imm(w):
    if ((w>>26)&3)!=1 or ((w>>25)&1)!=0 or ((w>>20)&1)!=0 or ((w>>24)&1)==0: return None
    rn=(w>>16)&0xF; rt=(w>>12)&0xF; off=w&0xFFF
    if ((w>>23)&1)==0: off=-off
    return rn,rt,off,'strb' if ((w>>22)&1) else 'str'

def is_push_lr(w): return (w & 0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def prologue(code,addr,window=0x8000):
    q=addr-START
    for p in range(q-(q%4),max(-1,q-window),-4):
        if p>=0 and p+4<=len(code) and is_push_lr(struct.unpack_from('<I',code,p)[0]): return START+p
    return max(START,addr-0x400)
def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def disasm(md,code,lo,hi):
    lo=max(START,lo&~3); hi=min(END,(hi+3)&~3); return list(md.disasm(code[lo-START:hi-START],lo))
def ascii_at(whole,p,n=180):
    if not 0<=p<len(whole): return None
    out=[]
    for b in whole[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else: return None
    s=''.join(out).strip(); return s if len(s)>=5 else None
def strings(ins,whole):
    rows=[]; seen=set()
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM: continue
        reg=x.operands[0].reg; low=x.operands[1].imm&0xffff
        for y in ins[i+1:i+9]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|low
                for p,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(whole,p)
                    if s and (p,s) not in seen: seen.add((p,s)); rows.append((p,label,s))
                break
    return rows
def contains_src_base(ins):
    low=SRC_BASE&0xffff; high=SRC_BASE>>16
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM or (x.operands[1].imm&0xffff)!=low: continue
        reg=x.operands[0].reg
        for y in ins[i+1:i+8]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM and (y.operands[1].imm&0xffff)==high: return True
    return False
def emit_callers(L,title,callers,md,code,whole):
    for addr in callers:
        e=prologue(code,addr); ins=disasm(md,code,max(e,addr-0x280),addr+0x180)
        L += [f'## {title} caller `0x{addr:08X}`',f'- nearest function: `0x{e:08X}`','```asm']+[fmt(x) for x in ins]+['```','']
        ss=strings(ins,whole)
        if ss: L += ['strings:']+[f'- {lab} `0x{p:08X}`: `{s[:170]}`' for p,lab,s in ss]+['']

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    whole=a.unpacked.read_bytes(); h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    code=whole[START:END]; md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    calls={AAA_FUNC:[],WRAPPER:[],PRODUCER:[],AWB_REFRESH:[]}; stores=[]
    for q in range(0,len(code)-4,4):
        w=struct.unpack_from('<I',code,q)[0]; addr=START+q; target=branch_target(addr,w)
        if target in calls: calls[target].append(addr)
        st=str_imm(w)
        if st and st[2] in SRC_OFFS: stores.append((addr,st))
    L=['# M11-P B2R gain producer provenance','',f'- SHA: `{h}`',f'- AAA function: `0x{AAA_FUNC:08X}`',f'- AWB wrapper: `0x{WRAPPER:08X}`',f'- producer: `0x{PRODUCER:08X}`',f'- AWB refresh: `0x{AWB_REFRESH:08X}`',f'- source state: `0x{SRC_BASE:08X} + 0x4D8/4DC/4E0/4E4`',f'- AAA-function direct BL callers: `{len(calls[AAA_FUNC])}`',f'- wrapper direct BL callers: `{len(calls[WRAPPER])}`',f'- producer direct BL callers: `{len(calls[PRODUCER])}`',f'- AWB-refresh direct BL callers: `{len(calls[AWB_REFRESH])}`','']
    emit_callers(L,'AAA function',calls[AAA_FUNC],md,code,whole)
    emit_callers(L,'AWB wrapper',calls[WRAPPER],md,code,whole)
    emit_callers(L,'producer',calls[PRODUCER],md,code,whole)
    emit_callers(L,'AWB refresh',calls[AWB_REFRESH],md,code,whole)
    grouped={}
    for addr,st in stores: grouped.setdefault(prologue(code,addr),[]).append((addr,st))
    for e,rows in sorted(grouped.items()):
        merged=[]
        for addr,st in rows:
            ins=disasm(md,code,addr-0x100,addr+0x100); merged.append((addr,st,contains_src_base(ins),ins))
        if not any(x[2] for x in merged): continue
        L += [f'## source-state writer candidate function `0x{e:08X}`','']
        for addr,st,tied,ins in merged:
            if not tied: continue
            rn,rt,off,kind=st; L += [f'### store `0x{addr:08X}`',f'- `{kind}` r{rt} -> [r{rn}, {off:+#x}]','```asm']+[fmt(x) for x in ins]+['```','']
    L += ['## Decision boundary','', 'Close B2R gain as ordinary per-shot WB when the AAA caller chain and destination-object provenance establish that the AWB-updated object is the still frame later consumed by B2R.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
