#!/usr/bin/env python3
"""Compare Leica M11 serializer builders by major object type and scalar width.

Exact jump-table calibration established that subtype pairs 1/2, 3/4 and 5/6
share one target per pair. The serializer has two major-type branches, each with
three width-specific builders. Therefore the six builder routines are NOT six
subtype implementations. This report uses the corrected organization and asks
what differs between major type 0 and major type 1 at each 1/2/4-byte width.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
# For the first five routines the next known builder start is an exact upper
# bound. The type1/word entry begins with a compare before its stack push, so a
# conservative fixed window is used rather than treating that push as a new
# function boundary.
BUILDERS=[
    (0,1,0x015A4024,0x015A4138),
    (0,2,0x015A4138,0x015A4284),
    (0,4,0x015A4284,0x015A43F0),
    (1,1,0x015A43F0,0x015A4464),
    (1,2,0x015A4464,0x015A4504),
    (1,4,0x015A4504,0x015A4644),
]


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w & 0x0F000000)!=0x0B000000: return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=0x1000000
    return off+8+(imm<<2)
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True; out=[]
    for i in md.disasm(d[s:min(len(d),e)],s):
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None: note=f' ; BL=0x{bt:08x}'
        out.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    return out
def opcode_signals(lines):
    keys=('ldrsb','ldrsh','sxtb','sxth','asr','ldrb','ldrh','ldr ','uxtb','uxth','strb','strh','str ','bl #')
    return [x for x in lines if any(k in x for k in keys)]
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    lines=['# M11-P R2A serializer builders by major type and width','',f'- SHA-256: `{h}`','- subtype pairs 1/2 = 1 byte, 3/4 = 2 bytes, 5/6 = 4 bytes (independently proven in gamma selector).','- both members of a subtype pair call the SAME serializer builder; odd/even subtype meaning is therefore not a width-builder distinction.','']
    for major,width,start,end in BUILDERS:
        body=disasm(d,start,end); sig=opcode_signals(body)
        lines += [f'## major type `{major}` / width `{width}` byte(s) — `0x{start:08x}`','',f'- analysis bound: `0x{start:08x}–0x{end:08x}`','- width/payload-sensitive signals:']
        if sig:
            for x in sig[:120]: lines.append(f'  - `{x}`')
        else: lines.append('  - none')
        lines += ['','```text']; lines.extend(body); lines += ['```','']
    lines += ['## Interpretation boundary','', 'This report can distinguish major-type serialization families and confirm width behavior. It cannot assign the odd/even meaning inside subtype pairs because both pair members deliberately converge on the same builder; that distinction must be recovered from object metadata/accessors or creation sites.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
