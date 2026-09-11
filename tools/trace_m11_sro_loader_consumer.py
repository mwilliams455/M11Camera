#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000
END=0x02000000
DELTA=0x3FAA87D0
SRO_OFF=0x002C9A98
THIRD_OFF=SRO_OFF+88
SRO_NAME=b"img/data/sro.bin\x00"
THIRD_Q9=[212,-165,-71,-73,676,85,-27,174,285]


def is_push_lr(w):
    return (w & 0x0fff0000)==0x092d0000 and (w&(1<<14))!=0

def nearest_prologue(code,addr,window=0x6000):
    q=addr-START
    for p in range(q-(q%4),max(-1,q-window),-4):
        if p>=0 and p+4<=len(code) and is_push_lr(struct.unpack_from('<I',code,p)[0]):
            return START+p
    return max(START,addr-0x400)

def fmt(x): return f"0x{x.address:08X}: {x.mnemonic} {x.op_str}".rstrip()

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

def nearby_strings(ins,whole):
    rows=[]; seen=set()
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM: continue
        reg=x.operands[0].reg; low=x.operands[1].imm&0xffff
        for y in ins[i+1:i+9]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|low
                for p,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(whole,p)
                    if s and (p,s) not in seen:
                        seen.add((p,s)); rows.append((p,label,s))
                break
    return rows

def decode_mov16(w,which):
    # A32 MOVW/MOVT A1: cond 00110{0/1}00 imm4 Rd imm12.
    tag=w & 0x0ff00000
    want=0x03000000 if which=='movw' else 0x03400000
    if tag!=want: return None
    rd=(w>>12)&0xf
    imm=((w>>4)&0xf000)|(w&0xfff)
    return rd,imm

def movw_movt_refs(code,target):
    refs=[]
    for q in range(0,len(code)-4,4):
        w=struct.unpack_from('<I',code,q)[0]
        m=decode_mov16(w,'movw')
        if not m: continue
        rd,low=m
        for r in range(q+4,min(q+32,len(code)-3),4):
            y=struct.unpack_from('<I',code,r)[0]
            mt=decode_mov16(y,'movt')
            if mt and mt[0]==rd:
                v=((mt[1]&0xffff)<<16)|(low&0xffff)
                if v==target: refs.append((START+q,START+r))
                break
    return refs

def all_occurrences(haystack,needle):
    out=[]; p=0
    while True:
        p=haystack.find(needle,p)
        if p<0: return out
        out.append(p); p+=1

def emit_refs(L,title,refs,md,code,whole):
    L += [f"## {title}",f"- MOVW/MOVT refs: `{len(refs)}`",""]
    for lo,hi in refs:
        e=nearest_prologue(code,lo)
        ins=disasm(md,code,max(e,lo-0x120),hi+0x180)
        L += [f"### ref `0x{lo:08X}` / function `0x{e:08X}`","```asm"]+[fmt(x) for x in ins]+["```",""]
        ss=nearby_strings(ins,whole)
        if ss: L += ["nearby strings:"]+[f"- {lab} `0x{p:08X}`: `{s[:170]}`" for p,lab,s in ss]+[""]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    whole=a.unpacked.read_bytes(); h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(f"unpacked SHA mismatch: {h}")
    code=whole[START:END]
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True

    name_hits=all_occurrences(whole,SRO_NAME)
    third_pat=b''.join(struct.pack('<i',x) for x in THIRD_Q9)
    third_hits=all_occurrences(whole,third_pat)

    records=[]
    for k in range(3):
        off=SRO_OFF+44*k
        coeff=list(struct.unpack_from('<9i',whole,off))
        scale,unk=struct.unpack_from('<HH',whole,off+36)
        kelvin=struct.unpack_from('<i',whole,off+40)[0]
        records.append((off,coeff,scale,unk,kelvin))

    targets=[]
    for off in name_hits:
        targets.append((f"sro filename runtime from file 0x{off:08X}",(off+DELTA)&0xffffffff))
    targets += [
        ("canonical SRO structure runtime",(SRO_OFF+DELTA)&0xffffffff),
        ("canonical third-record runtime",(THIRD_OFF+DELTA)&0xffffffff),
    ]

    L=["# M11-P SRO loader / consumer provenance trace","",f"- SHA: `{h}`",f"- SRO file offset: `0x{SRO_OFF:08X}`",f"- third record file offset: `0x{THIRD_OFF:08X}`",f"- relocation delta used for image pointers: `0x{DELTA:08X}`",""]
    L += ["## Canonical 132-byte SRO structure",""]
    for i,(off,coeff,scale,unk,kelvin) in enumerate(records,1):
        L += [f"### record {i} @ `0x{off:08X}`",f"- coeff: `{coeff}`",f"- scaleCode: `{scale}`",f"- unknown26: `{unk}`",f"- kelvin: `{kelvin}`",""]
    L += ["## Exact payload/string occurrences",f"- `img/data/sro.bin` hits: `{[hex(x) for x in name_hits]}`",f"- exact corrected third-Q9 36-byte hits: `{[hex(x) for x in third_hits]}`",""]

    for label,target in targets:
        refs=movw_movt_refs(code,target)
        emit_refs(L,f"References to {label} = `0x{target:08X}`",refs,md,code,whole)
        literal=struct.pack('<I',target)
        lits=[p for p in all_occurrences(whole,literal) if START<=p<END]
        L += [f"- literal 32-bit occurrences in A32 code window: `{[hex(x) for x in lits[:64]]}`",""]

    L += ["## Decision boundary","",
          "A filename xref can identify the SRO load path, while a direct runtime-data xref can identify a static consumer. Neither alone proves the third Q9 record is active in the still pixel path. Promotion requires tying a loaded destination or direct record pointer to a named B2R/R2Y/ColorSpec consumer used by still rendering.",""]
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)

if __name__=='__main__': main()
