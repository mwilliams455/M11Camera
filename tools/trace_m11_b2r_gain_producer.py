#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000
END=0x02000000
PRODUCER=0x016DCEB0
SRC_BASE=0x4342F91C
SRC_OFFS={0x4D8,0x4DC,0x4E0,0x4E4}
DELTA=0x3FAA87D0

def sx(v,bits):
    sign=1<<(bits-1)
    return (v^sign)-sign

def branch_target(addr,w):
    if ((w>>25)&0x7)!=0x5 or ((w>>24)&1)!=1:
        return None
    return (addr+8 + sx(w&0xFFFFFF,24)*4) & 0xFFFFFFFF

def str_imm(w):
    # A32 STR/STRB immediate, pre-indexed or offset form.
    if ((w>>26)&3)!=1 or ((w>>25)&1)!=0 or ((w>>20)&1)!=0:
        return None
    if ((w>>24)&1)==0:
        return None
    rn=(w>>16)&0xF; rt=(w>>12)&0xF; off=w&0xFFF
    if ((w>>23)&1)==0: off=-off
    return rn,rt,off,'strb' if ((w>>22)&1) else 'str'

def is_push_lr(w):
    return (w & 0x0fff0000)==0x092d0000 and (w&(1<<14))!=0

def prologue(code,addr,window=0x8000):
    q=addr-START
    for p in range(q-(q%4),max(-1,q-window),-4):
        if p>=0 and p+4<=len(code) and is_push_lr(struct.unpack_from('<I',code,p)[0]):
            return START+p
    return max(START,addr-0x400)

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def disasm(md,code,lo,hi):
    lo=max(START,lo&~3); hi=min(END,(hi+3)&~3)
    return list(md.disasm(code[lo-START:hi-START],lo))

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
        reg=x.operands[0].reg; low=x.operands[1].imm & 0xFFFF
        for y in ins[i+1:i+9]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xFFFF)<<16)|low
                for p,label in (((v-DELTA)&0xFFFFFFFF,'translated'),(v,'raw')):
                    s=ascii_at(whole,p)
                    if s and (p,s) not in seen:
                        seen.add((p,s)); rows.append((p,label,s))
                break
    return rows

def contains_src_base(ins):
    low=SRC_BASE&0xFFFF; high=SRC_BASE>>16
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM: continue
        if (x.operands[1].imm&0xFFFF)!=low: continue
        reg=x.operands[0].reg
        for y in ins[i+1:i+8]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM and (y.operands[1].imm&0xFFFF)==high:
                return True
    return False

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    whole=a.unpacked.read_bytes(); h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    code=whole[START:END]
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    callers=[]; stores=[]
    for q in range(0,len(code)-4,4):
        w=struct.unpack_from('<I',code,q)[0]; addr=START+q
        if branch_target(addr,w)==PRODUCER: callers.append(addr)
        st=str_imm(w)
        if st and st[2] in SRC_OFFS: stores.append((addr,st))

    L=['# M11-P B2R gain producer provenance','',f'- SHA: `{h}`',f'- producer: `0x{PRODUCER:08X}`',f'- source state: `0x{SRC_BASE:08X} + 0x4D8/4DC/4E0/4E4`',f'- direct BL callers: `{len(callers)}`',f'- structural source-offset stores: `{len(stores)}`','']
    for addr in callers:
        e=prologue(code,addr)
        ins=disasm(md,code,max(e,addr-0x180),addr+0x100)
        L += [f'## producer caller `0x{addr:08X}`',f'- nearest function: `0x{e:08X}`','```asm']+[fmt(x) for x in ins]+['```','']
        ss=strings(ins,whole)
        if ss: L += ['strings:']+[f'- {lab} `0x{p:08X}`: `{s[:170]}`' for p,lab,s in ss]+['']

    grouped={}
    for addr,st in stores:
        e=prologue(code,addr)
        grouped.setdefault(e,[]).append((addr,st))
    for e,rows in sorted(grouped.items()):
        # Filter report emphasis by whether nearby code actually constructs source absolute base.
        merged=[]
        for addr,st in rows:
            ins=disasm(md,code,addr-0x100,addr+0x100)
            tied=contains_src_base(ins)
            merged.append((addr,st,tied,ins))
        if not any(x[2] for x in merged): continue
        L += [f'## source-state writer candidate function `0x{e:08X}`',f'- stores in function: `{len(rows)}`','']
        for addr,st,tied,ins in merged:
            if not tied: continue
            rn,rt,off,kind=st
            L += [f'### store `0x{addr:08X}`',f'- `{kind}` r{rt} -> [r{rn}, {off:+#x}]',f'- source-base construction nearby: `{tied}`','```asm']+[fmt(x) for x in ins]+['```','']
            ss=strings(ins,whole)
            if ss: L += ['strings:']+[f'- {lab} `0x{p:08X}`: `{s[:170]}`' for p,lab,s in ss]+['']

    L += ['## Decision boundary','',
          'The +0x1AC/+0x1AE/+0x1B0 fields are now known to be populated by 0x016DCEB0 from global source-state values. Classify them as ordinary WB only if the caller/source writer chain ties those source values to AWB/gray-balance state; otherwise keep them as an unresolved Leica-domain gain.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
