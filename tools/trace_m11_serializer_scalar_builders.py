#!/usr/bin/env python3
"""Compare the six Leica M11 scalar subtype builders used by 0x015a6374.

The serializer dispatches subtype pairs 1/2, 3/4, 5/6. Gamma independently
packs those pairs as 1, 2 and 4-byte values. This pass traces the six direct
builder targets to determine what distinguishes the two members of each width
pair (for example signedness) from Leica-primary code rather than inference.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
BUILDERS=[
    (1,0x015A4504),
    (2,0x015A4464),
    (3,0x015A43F0),
    (4,0x015A4284),
    (5,0x015A4138),
    (6,0x015A4024),
]


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w & 0x0F000000)!=0x0B000000: return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i): return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def next_prologue(d,s,max_len=0x500):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(len(d)-4,s+max_len),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i): return o
    return min(len(d),s+max_len)
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True; out=[]
    for i in md.disasm(d[s:e],s):
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None: note=f' ; BL=0x{bt:08x}'
        out.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    return out

def opcode_signals(lines):
    keys=('ldrsb','ldrsh','sxtb','sxth','asr','ldrb','ldrh','uxtb','uxth','strb','strh','str ')
    return [x for x in lines if any(k in x for k in keys)]
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    lines=['# M11-P R2A serializer scalar subtype builder comparison','',f'- SHA-256: `{h}`','- Gamma independently groups subtypes 1/2 as 1-byte, 3/4 as 2-byte, 5/6 as 4-byte.','- This report tests the within-pair distinction from builder instructions.','']
    for subtype,start in BUILDERS:
        end=next_prologue(d,start); body=disasm(d,start,end)
        lines += [f'## subtype `{subtype}` builder `0x{start:08x}`','',f'- next-prologue bound: `0x{end:08x}` (`0x{end-start:x}` bytes)','- width/sign-sensitive instruction signals:']
        sig=opcode_signals(body)
        if sig:
            for x in sig: lines.append(f'  - `{x}`')
        else: lines.append('  - none')
        lines += ['','```text']; lines.extend(body); lines += ['```','']
    lines += ['## Interpretation boundary','', 'Signed/unsigned or other subtype meanings are promoted only when paired builders differ in a consistent sign/extension/range behavior. Width grouping itself is independently established by gamma packing.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
