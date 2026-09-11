#!/usr/bin/env python3
"""Map Leica M11-P R2YS category lookups and low-level calls around Cat24..Cat42.

The known YC wrapper (0x0172DFC0) and CSP wrapper (around 0x01731970) live in a
compact configuration region.  This report scans that region for calls to the
proven R2YS category lookup routine 0x0178D0A8, recovers simple immediate
category arguments where possible, groups calls by A32 function, and lists
outbound calls into the low-level 0x01Bxxxxx R2Y driver family.

This is configuration/dataflow evidence.  Function/programming order alone is
not promoted to silicon pixel-stage order.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
LOOKUP=0x0178D0A8
LO=0x0172D000
HI=0x01733000
KNOWN_YCC=0x0172DFC0
KNOWN_CSP_CALL=0x01731DB0


def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def is_push_lr(w): return (w & 0xFFFF4000)==0xE92D4000

def bl_target(p,w):
    if ((w>>28)&0xF)==0xF or ((w>>25)&7)!=5 or ((w>>24)&1)==0: return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=1<<24
    return (p+8+(imm<<2))&0xffffffff

def entry_before(d,p,back=0x3000):
    lo=max(0,p-back)&~3; out=None
    for q in range(lo,p+1,4):
        if is_push_lr(u32(d,q)): out=q
    return out if out is not None else lo

def extent(d,e,hi=HI,maxlen=0x3000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for i in md.disasm(d[e:min(len(d),e+maxlen,hi)],e):
        if i.address>e+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or (i.mnemonic=='bx' and i.op_str.strip()=='lr')):
            return i.address+4
    return min(len(d),e+maxlen,hi)

def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    return list(md.disasm(d[s:e],s))

def fmt(i): return f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'

def immediate_category(insns,idx):
    # R2YS lookup wrappers seen so far load category as a small immediate into
    # r1 before BL. Track simple mov/movw r1,#imm over the preceding window.
    val=None
    for j in range(max(0,idx-18),idx):
        i=insns[j]
        if i.mnemonic in ('mov','movw') and len(i.operands)>=2:
            if i.operands[0].type==ARM_OP_REG and i.reg_name(i.operands[0].reg)=='r1' and i.operands[1].type==ARM_OP_IMM:
                val=i.operands[1].imm & 0xffff
        elif i.mnemonic=='movt' and len(i.operands)>=2 and i.operands[0].type==ARM_OP_REG and i.reg_name(i.operands[0].reg)=='r1':
            # Categories of interest are small; a MOVT means this is probably
            # not the category argument we want.
            val=None
    return val

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args(); d=a.unpacked.read_bytes(); sha=hashlib.sha256(d).hexdigest()
    if sha!=EXPECTED: raise ValueError(sha)
    allins=disasm(d,LO,HI)
    # Split by discovered PUSH/LR entries in the region.
    entries=sorted({i.address for i in allins if is_push_lr(u32(d,i.address))})
    funcs=[]
    for e in entries:
        en=extent(d,e)
        if en<=e: continue
        ins=disasm(d,e,en)
        lookups=[]; calls=[]
        for n,i in enumerate(ins):
            t=bl_target(i.address,u32(d,i.address))
            if t is None: continue
            calls.append((i.address,t))
            if t==LOOKUP:
                lookups.append((i.address,immediate_category(ins,n)))
        if lookups or any(0x01B00000<=t<0x01C00000 for _,t in calls):
            funcs.append((e,en,ins,lookups,calls))

    lines=['# M11-P R2Y Cat24..Cat42 wrapper-region trace','',f'- SHA-256: `{sha}`',f'- scan region: `0x{LO:08x}..0x{HI:08x}`',f'- proven R2YS lookup: `0x{LOOKUP:08x}`',f'- known YC wrapper: `0x{KNOWN_YCC:08x}`',f'- known CSP setter callsite: `0x{KNOWN_CSP_CALL:08x}`','']
    lines += ['## Compact function map','']
    for e,en,ins,lookups,calls in funcs:
        cats=[c for _,c in lookups if c is not None]
        low=[(cs,t) for cs,t in calls if 0x01B00000<=t<0x01C00000]
        lines.append(f'- `0x{e:08x}..0x{en:08x}` categories `{cats}` low-level calls `{[(hex(cs),hex(t)) for cs,t in low]}`')
    lines += ['','## Detailed functions','']
    for e,en,ins,lookups,calls in funcs:
        cats=[c for _,c in lookups if c is not None]
        if not cats and not (e<=KNOWN_CSP_CALL<en) and e!=KNOWN_YCC: continue
        lines += [f'### `0x{e:08x}..0x{en:08x}`','',f'- category lookups: `{[(hex(cs),c) for cs,c in lookups]}`']
        low=[(cs,t) for cs,t in calls if 0x01B00000<=t<0x01C00000]
        lines.append(f'- low-level 0x01Bxxxxx calls: `{[(hex(cs),hex(t)) for cs,t in low]}`')
        lines += ['```asm']+[fmt(i) for i in ins]+['```','']
    lines += ['## Interpretation boundary','', 'This trace can prove which R2YS categories are assembled by which Leica wrappers and which low-level R2Y driver functions receive them. It does not, by itself, prove hidden silicon pixel-stage order; combine it with the public R2Y register topology and API signal-domain semantics.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)); print(a.output)
if __name__=='__main__': main()
