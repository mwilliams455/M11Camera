#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000
END=0x02000000
TARGETS={0x1AC,0x1AE,0x1B0}
DELTA=0x3FAA87D0


def prologue(insns, idx, window=0x2000):
    addr=insns[idx].address; best=None
    j=idx
    while j>=0 and addr-insns[j].address<=window:
        x=insns[j]; s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s):
            best=x.address; break
        j-=1
    return best

def ascii_at(d,p,n=160):
    if not 0<=p<len(d): return None
    o=[]
    for b in d[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: o.append(chr(b))
        else: return None
    s=''.join(o).strip(); return s if len(s)>=5 else None

def strings_near(insns,d,i0,i1):
    out=[]; seen=set()
    for i in range(i0,min(i1,len(insns))):
        x=insns[i]
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM: continue
        reg=x.operands[0].reg; lo=x.operands[1].imm & 0xffff
        for y in insns[i+1:min(i+8,len(insns))]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|lo
                for off,lab in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(d,off)
                    if s and (off,s) not in seen:
                        seen.add((off,s)); out.append((off,lab,s))
                break
    return out

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(f'unpacked SHA mismatch {h}')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    ins=list(md.disasm(d[START:END],START))
    direct=[]; adds=[]
    for i,x in enumerate(ins):
        if x.mnemonic in ('strh','str'):
            for op in x.operands:
                if op.type==ARM_OP_MEM and op.mem.disp in TARGETS:
                    direct.append((i,op.mem.disp))
        if x.mnemonic in ('add','sub') and len(x.operands)>=3 and x.operands[2].type==ARM_OP_IMM and abs(x.operands[2].imm) in TARGETS:
            # Compiler commonly materialises field address then stores at +0/+2/+4.
            dst=x.operands[0].reg if x.operands[0].type==ARM_OP_REG else 0
            for j in range(i+1,min(i+12,len(ins))):
                y=ins[j]
                if y.mnemonic in ('strh','str'):
                    for op in y.operands:
                        if op.type==ARM_OP_MEM and op.mem.base==dst and op.mem.disp in (0,2,4):
                            adds.append((i,j,x.operands[2].imm,op.mem.disp)); break
    # dedupe by store address
    cand={}
    for i,off in direct: cand[ins[i].address]=(i,f'direct mem +0x{off:X}')
    for i,j,off,disp in adds: cand.setdefault(ins[j].address,(j,f'address materialised +0x{off:X}, store +0x{disp:X}'))

    L=['# M11-P B2R WB triplet writer trace','',f'- SHA: `{h}`',f'- scan: `0x{START:08X}..0x{END:08X}`',f'- target frame offsets: `+0x1AC/+0x1AE/+0x1B0`',f'- candidate stores: `{len(cand)}`','']
    groups={}
    for addr,(i,why) in sorted(cand.items()):
        e=prologue(ins,i) or max(START,addr-0x400)
        groups.setdefault(e,[]).append((i,why))
    for e,rows in sorted(groups.items()):
        L += [f'## candidate function `0x{e:08X}`',f'- stores: `{len(rows)}`','']
        lo=max(0,min(i for i,_ in rows)-50); hi=min(len(ins),max(i for i,_ in rows)+60)
        ss=strings_near(ins,d,lo,hi)
        if ss:
            L += ['### nearby strings','']+[f'- {lab} `0x{off:08X}`: `{s[:150]}`' for off,lab,s in ss]+['']
        for i,why in rows:
            L += [f'### store `{fmt(ins[i])}`',f'- match: {why}','```asm']+[fmt(z) for z in ins[max(0,i-26):min(len(ins),i+30)]]+['```','']
    L += ['## Interpretation boundary','',
          'A direct offset match is only a structural candidate. Accept it as the still B2R WB producer only after the object base is tied to the still frame object passed through global 0x43433774, or after a named AWB/WB producer is independently identified.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
