#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from extract_m11p_forensics import parse_r2y, map_bytes, sha

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
WRAPPER = 0x0172EC18
LOOKUP = 0x0178D0A8


def u32(d, p): return struct.unpack_from('<I', d, p)[0]

def bl_target(p, w):
    if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 7) != 5 or ((w >> 24) & 1) == 0: return None
    x = w & 0xFFFFFF
    if x & 0x800000: x -= 1 << 24
    return (p + 8 + (x << 2)) & 0xFFFFFFFF

def md():
    c=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.detail=True; c.skipdata=True; return c

def disasm(d,a,b): return list(md().disasm(d[a:b],a))
def fn_end(d,e,cap=0x5000):
    for i in disasm(d,e,min(len(d),e+cap)):
        if i.address>e+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or (i.mnemonic=='bx' and i.op_str.strip()=='lr')): return i.address+4
    return min(len(d),e+cap)
def rn(i,o): return i.reg_name(o.reg) if o.type==ARM_OP_REG else None
def iv(o): return int(o.imm) if o.type==ARM_OP_IMM else None

def request_cat(ins, idx):
    # All observed MCC requests store category at fp-0x21c, which is request+8
    # for r0 = fp-0x224. Recover the source register constant directly.
    for j in range(idx-1,max(-1,idx-30),-1):
        i=ins[j]
        if not i.mnemonic.startswith('str') or len(i.operands)<2: continue
        m=i.operands[1]
        if m.type!=ARM_OP_MEM: continue
        base=i.reg_name(m.mem.base) if m.mem.base else ''
        if base not in ('fp','r11') or int(m.mem.disp)!=-0x21c: continue
        src=rn(i,i.operands[0])
        if not src: continue
        for k in range(j-1,max(-1,j-12),-1):
            q=ins[k]
            if len(q.operands)>=2 and rn(q,q.operands[0])==src and q.mnemonic in ('mov','movw'):
                x=iv(q.operands[1])
                if x is not None: return x & 0xffff
    return None

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); digest=hashlib.sha256(d).hexdigest()
    if digest!=EXPECTED_SHA: raise ValueError(digest)
    base,_,_,descs=parse_r2y(d)
    counts=Counter(int(x['category']) for x in descs)
    sizes={}
    for x in descs: sizes.setdefault(int(x['category']),set()).add(int(x['map_size']))
    end=fn_end(d,WRAPPER); ins=disasm(d,WRAPPER,end)
    req=[]
    for n,i in enumerate(ins):
        if bl_target(i.address,u32(d,i.address))==LOOKUP:
            c=request_cat(ins,n); req.append((i.address,c))
    lines=['# M11 R2YS MCC category diagnostic','',f'- SHA: `{digest}`',f'- wrapper: `0x{WRAPPER:08x}..0x{end:08x}`','',
           '## Literal resolver requests in wrapper','']
    for p,c in req: lines.append(f'- `0x{p:08x}` -> category `{c}` / `{hex(c) if c is not None else None}`')
    lines += ['', '## Full R2YS category inventory','', '| category | descriptors | map sizes |','| ---: | ---: | --- |']
    for c in sorted(counts): lines.append(f'| {c} | {counts[c]} | `{sorted(sizes[c])}` |')
    lines += ['', '## Requested-category lookup','']
    for _,c in req:
        rows=[x for x in descs if int(x['category'])==c] if c is not None else []
        lines += [f'### category {c}',f'- descriptors: `{len(rows)}`']
        for x in rows[:12]:
            raw=map_bytes(d,base,x)
            lines.append(f"- idx `{x['index']}` flags `{x['flags_hex']}` size `{len(raw)}` deps `{x['dependencies_s32']}` sha `{sha(raw)}`")
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
