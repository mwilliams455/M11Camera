#!/usr/bin/env python3
"""Focused Leica M11-P Category-24 YC consumer / YBLEND split probe.

The calibrated contextual trace identifies 0x01B624AC as the probable YC
3x3-matrix programmer.  This probe keeps the question narrow:

* dump the complete candidate and its sole direct Leica caller context;
* enumerate halfword reads from the candidate's control payload;
* enumerate writes to the five packed YC matrix registers;
* find nearby low-level functions that write YBLEND (+0x120), so a separate
  blend consumer can be distinguished from the 18-byte Category-24 matrix.

No renderer behaviour is changed by this probe.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
YCC_SETTER = 0x01B624AC
YCC_CALLSITE = 0x0172E238
CSP_SETTER = 0x01B68B80
YC_OFFSETS = {0x100,0x104,0x108,0x10C,0x110}
YBLEND = 0x120


def u32(data,p): return struct.unpack_from('<I',data,p)[0]

def is_push_lr(w): return (w & 0xFFFF4000) == 0xE92D4000

def entry_before(data,p,back=0x1800):
    lo=max(0,p-back)&~3; out=lo
    for q in range(lo,p+1,4):
        if is_push_lr(u32(data,q)): out=q
    return out

def decode_sdt_imm(w):
    if ((w>>28)&0xF)==0xF or ((w>>26)&3)!=1 or ((w>>25)&1): return None
    return bool((w>>20)&1), bool((w>>23)&1), (w>>16)&0xF, (w>>12)&0xF, w&0xFFF

def bl_callers(data,target):
    out=[]
    for p in range(0,len(data)&~3,4):
        w=u32(data,p)
        if ((w>>28)&0xF)==0xF or ((w>>25)&7)!=5 or ((w>>24)&1)==0: continue
        imm=w&0xFFFFFF
        if imm&0x800000: imm-=1<<24
        if ((p+8+(imm<<2))&0xFFFFFFFF)==target: out.append(p)
    return out

def disasm(data,lo,hi):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    return list(md.disasm(data[lo:hi],lo))

def fmt(ins): return f"{ins.address:#010x}: {ins.mnemonic} {ins.op_str}"

def function_extent(data,entry,max_len=0x1000):
    ins=disasm(data,entry,min(len(data),entry+max_len))
    for i in ins:
        # Leica GCC functions normally return with pop {...,pc} or bx lr.
        if i.address>entry+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or (i.mnemonic=='bx' and i.op_str.strip()=='lr')):
            return i.address+4
    return min(len(data),entry+max_len)

def local_yblend_functions(data,lo,hi):
    groups=defaultdict(list)
    for p in range(max(0,lo)&~3,min(len(data),hi)&~3,4):
        d=decode_sdt_imm(u32(data,p))
        if not d: continue
        load,up,rn,rt,imm=d
        if load or not up or imm!=YBLEND: continue
        e=entry_before(data,p,0x1000)
        groups[e].append((p,rn,rt))
    rows=[]
    for e,hits in groups.items():
        rows.append((e,hits,bl_callers(data,e)))
    rows.sort(key=lambda x:(abs(x[0]-YCC_SETTER),-len(x[1])))
    return rows

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); sha=hashlib.sha256(data).hexdigest()
    if sha!=EXPECTED_SHA: raise ValueError(f'unexpected unpacked SHA-256 {sha}')

    end=function_extent(data,YCC_SETTER,0x1000)
    yins=disasm(data,YCC_SETTER,end)
    wrapper_entry=entry_before(data,YCC_CALLSITE,0x1800)
    wrapper_end=function_extent(data,wrapper_entry,0x1800)
    wins=disasm(data,wrapper_entry,wrapper_end)

    payload_reads=[]; yc_stores=[]; yblend_stores=[]
    for ins in yins:
        if ins.mnemonic.startswith('ldrh') or ins.mnemonic.startswith('ldrsh'):
            payload_reads.append(fmt(ins))
        w=u32(data,ins.address); d=decode_sdt_imm(w)
        if d:
            load,up,rn,rt,imm=d
            if not load and up and imm in YC_OFFSETS: yc_stores.append(fmt(ins))
            if not load and up and imm==YBLEND: yblend_stores.append(fmt(ins))

    near=local_yblend_functions(data,YCC_SETTER-0x30000,YCC_SETTER+0x30000)
    lines=[
      '# M11-P Category-24 YC matrix / YBLEND focused trace','',
      f'- exact unpacked SHA-256: `{sha}`',
      f'- YC candidate entry: `0x{YCC_SETTER:08x}`',
      f'- candidate extent: `0x{YCC_SETTER:08x}..0x{end:08x}`',
      f'- direct callers: `{[hex(x) for x in bl_callers(data,YCC_SETTER)]}`',
      f'- known callsite: `0x{YCC_CALLSITE:08x}`; enclosing wrapper entry: `0x{wrapper_entry:08x}`',
      f'- halfword payload-read instructions: `{len(payload_reads)}`',
      f'- YC-register store instructions: `{len(yc_stores)}`',
      f'- YBLEND stores inside YC candidate: `{len(yblend_stores)}`','',
      '## Candidate payload halfword reads','']
    lines += [f'- `{x}`' for x in payload_reads]
    lines += ['', '## Candidate YC register writes',''] + [f'- `{x}`' for x in yc_stores]
    lines += ['', '## Candidate YBLEND writes',''] + ([f'- `{x}`' for x in yblend_stores] or ['None.'])
    lines += ['', '## Complete YC candidate disassembly','```asm'] + [fmt(i) for i in yins] + ['```','']
    lines += ['## Leica caller/wrapper context','```asm'] + [fmt(i) for i in wins] + ['```','']
    lines += ['## Nearby low-level +0x120 (YBLEND-shaped) writers','']
    for idx,(e,hits,callers) in enumerate(near[:20],1):
        lines += [f'### {idx}. `0x{e:08x}`',f'- stores: `{[(hex(p),"r"+str(rn),"r"+str(rt)) for p,rn,rt in hits]}`',f'- direct callers: `{[hex(x) for x in callers]}`','']
        eend=function_extent(data,e,0x500)
        lines += ['```asm']+[fmt(i) for i in disasm(data,e,eend)][:220]+['```','']
    lines += ['## Evidence boundary','',
      'A 9-coefficient payload mapped into the five packed YC registers with no +0x120 write supports Category 24 as the matrix-only consumer. A separate coherent +0x120 writer supports a matrix/blend control split. This still does not, by itself, prove silicon pixel-stage ordering versus CSP.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)); print(a.output)

if __name__=='__main__': main()
