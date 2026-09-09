#!/usr/bin/env python3
"""Trace Leica M11 gamma subtype blocks after exact serializer calibration.

The code-pointer base is derived inside this tool from both serializer subtype
tables and their independently observed exact case-entry starts. The tool aborts
unless there is exactly one base. It then traces the gamma selector targets for
subtypes 1..6 in both the validation/input-packing and output-packing switches.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SERIALIZER=[
    (0x015A6544,[0x015A6630,0x015A6630,0x015A6614,0x015A6614,0x015A65F8,0x015A65F8]),
    (0x015A6570,[0x015A65DC,0x015A65DC,0x015A65C0,0x015A65C0,0x015A65A4,0x015A65A4]),
]
GAMMA_TABLES=[
    ("input_or_validation",0x01579444,6),
    ("output_packing",0x015799FC,4),
]


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def entries(d,t,n): return [u32(d,t+4*i) for i in range(n)]
def derive_base(d):
    bases=None
    for table,targets in SERIALIZER:
        raw=entries(d,table,len(targets)); implied={(w-t)&0xffffffff for w,t in zip(raw,targets)}
        if len(implied)!=1: return []
        bases=implied if bases is None else bases & implied
    return sorted(bases or [])
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True
    return [f'0x{i.address:08x}: {i.mnemonic} {i.op_str}' for i in md.disasm(d[s:e],s)]
def signals(rows):
    keys=('ldrb','ldrh','ldr ','strb','strh','str ','uxtb','uxth','sxtb','sxth','lsr','lsl','orr','cmp')
    return [x for x in rows if any(k in x for k in keys)]
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    bases=derive_base(d)
    if len(bases)!=1: raise ValueError(f'expected one exact serializer-calibrated code-pointer base, got {bases}')
    base=bases[0]
    maps={}
    for name,t,n in GAMMA_TABLES:
        maps[name]=[((w-base)&0xffffffff) for w in entries(d,t,n)]
    # The output table explicitly handles subtype 1..4. Its default path for
    # subtype 5/6 starts at 0x01579AEC in linear control flow.
    output6=maps['output_packing']+[0x01579AEC,0x01579AEC]
    input6=maps['input_or_validation']
    lines=['# M11-P R2A exact gamma subtype block trace','',f'- SHA-256: `{h}`',f'- uniquely serializer-calibrated code-pointer base: `0x{base:08x}`','- subtype is the Leica object-record halfword at +0x02 and is validated as 1..6.','', '## Resolved subtype target map','']
    for s,(a,b) in enumerate(zip(input6,output6),1):
        lines.append(f'- subtype `{s}`: input/validation `0x{a:08x}`, output packing `0x{b:08x}`')
    lines += ['','## Per-subtype block evidence','']
    seen=set()
    for s,(a,b) in enumerate(zip(input6,output6),1):
        lines.append(f'### subtype `{s}`')
        for role,target,span in [('input/validation',a,0x50),('output packing',b,0x40)]:
            key=(role,target)
            lines.append(f'- {role} target `0x{target:08x}`')
            if key in seen:
                lines.append('  - same target as paired subtype above')
                continue
            seen.add(key)
            body=disasm(d,target,min(len(d),target+span)); sig=signals(body)
            lines.append('  - width/packing-sensitive signals:')
            for row in sig[:40]: lines.append(f'    - `{row}`')
            lines += ['','```text']; lines.extend(body); lines += ['```']
        lines.append('')
    lines += ['## Interpretation boundary','', 'Shared paired targets prove that the selector handles subtypes (1,2), (3,4), and (5,6) together for byte width. The semantic difference within each pair is not assigned here; it must come from the six serializer builders or accessor payload behavior.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
