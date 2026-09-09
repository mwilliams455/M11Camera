#!/usr/bin/env python3
"""Trace Leica M11-P object accessors used by gamma operations 1 and 2.

Gamma operation 2 reaches getter-family targets while operation 1 reaches
setter-family targets after parsing typed payload bytes. This pass follows
simple unconditional entry trampolines, disassembles each target through a
return/bounded window, and reports memory load/store/call evidence. It does not
pre-label the functions as getters/setters in the evidence sections.
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TARGETS=[
 ('op2_major0',0x0169D980),('op2_major1',0x0169DB90),
 ('op2_major2_data',0x0169E15C),('op2_major2_aux',0x0169E2D0),
 ('op1_major0',0x0169FCAC),('op1_major1',0x0169FFF4),('op1_major2',0x016A08CC),
]

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def branch_target(off,w):
    # unconditional A32 B only (cond=AL, op 1010)
    if (w&0xff000000)!=0xea000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def resolve_entry(d,s,max_hops=4):
    chain=[s];cur=s
    for _ in range(max_hops):
        t=branch_target(cur,u32(d,cur))
        if t is None or t in chain:break
        chain.append(t);cur=t
    return chain
def body(d,s,maxbytes=0x500):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[s:min(len(d),s+maxbytes)],s):
        out.append(i)
        if (i.mnemonic=='bx' and i.op_str.strip()=='lr') or (i.mnemonic.startswith('pop') and 'pc' in i.op_str):break
    return out
def classify(ins):
    loads=[];stores=[];calls=[]
    for i in ins:
        if i.mnemonic.startswith('ldr'):loads.append(i)
        if i.mnemonic.startswith('str'):stores.append(i)
        if i.address+4<=0xffffffff:
            # caller checks bounds in report before invoking u32
            pass
    return loads,stores,calls
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    lines=['# M11-P R2A gamma object-access helper semantics','',f'- SHA-256: `{h}`','- labels `op1_*` / `op2_*` describe only which gamma operation reaches each target; semantic getter/setter naming is withheld until body evidence.','']
    for label,start in TARGETS:
        chain=resolve_entry(d,start);entry=chain[-1];ins=body(d,entry);loads=[];stores=[];calls=[]
        for i in ins:
            if i.mnemonic.startswith('ldr'):loads.append(i)
            if i.mnemonic.startswith('str'):stores.append(i)
            if i.address+4<=len(d):
                bt=bl_target(i.address,u32(d,i.address))
                if bt is not None:calls.append((i,bt))
        lines += [f'## `{label}` exposed target `0x{start:08x}`','', '- entry chain: '+ ' -> '.join(f'`0x{x:08x}`' for x in chain), f'- analyzed entry: `0x{entry:08x}`', f'- body instructions through first return: `{len(ins)}`', f'- memory loads: `{len(loads)}`; memory stores: `{len(stores)}`; direct calls: `{len(calls)}`','', '### Memory-write evidence']
        if stores:
            for i in stores:lines.append(f'- `0x{i.address:08x}: {i.mnemonic} {i.op_str}`')
        else:lines.append('- none before first return')
        lines += ['', '### Memory-read evidence']
        for i in loads[:100]:lines.append(f'- `0x{i.address:08x}: {i.mnemonic} {i.op_str}`')
        lines += ['', '### Direct callees']
        for i,t in calls:lines.append(f'- `0x{i.address:08x}` -> `0x{t:08x}`')
        lines += ['', '```text']
        for i in ins:lines.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}')
        lines += ['```','']
    lines += ['## Interpretation boundary','', 'A helper is promoted as mutating only when its own resolved body or an unambiguous direct callee performs a store into object/payload state derived from the supplied object slot. Generic stack stores do not count as object mutation.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
