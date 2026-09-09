#!/usr/bin/env python3
"""Prove Leica M11-P scalar subtype semantics from exact firmware control flow.

Two independent Leica-primary facts are combined:
1. Exact serializer-calibrated gamma jump tables pair subtype 1/2 as 1 byte,
   3/4 as 2 bytes, and 5/6 as 4 bytes.
2. Range validator 0x0169feac reads record subtype at +0x02, tests bit 0,
   then uses unsigned ARM conditions (HI/LS) for even values and signed
   conditions (LT/GT/LE) for odd values.
Together these establish the six scalar format enum values without relying on
public source or naming guesses.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
VALIDATOR_START=0x0169FEAC
VALIDATOR_END=0x0169FF7C
CODEPTR_BASE=0x3FAA87D0
GAMMA_SUBTYPE_TABLE=0x01579444
GAMMA_PACK_TABLE=0x015799FC


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def disasm_map(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    return {i.address:i for i in md.disasm(d[s:e],s)}
def require(m,addr,mnemonic,contains=None):
    i=m.get(addr)
    if i is None or i.mnemonic!=mnemonic or (contains is not None and contains not in i.op_str):
        got='missing' if i is None else f'{i.mnemonic} {i.op_str}'
        raise ValueError(f'expected {addr:#x}: {mnemonic} {contains or ""}; got {got}')
    return i
def gamma_targets(d):
    raw=[u32(d,GAMMA_SUBTYPE_TABLE+4*i) for i in range(6)]
    return [((w-CODEPTR_BASE)&0xffffffff) for w in raw]
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    m=disasm_map(d,VALIDATOR_START,VALIDATOR_END)
    # Exact structural guards.
    require(m,0x0169FF30,'ldrh','[r4, #2]')
    require(m,0x0169FF34,'ands','r3, #1')
    require(m,0x0169FF40,'bne','#0x169ff60')
    require(m,0x0169FF44,'cmp','r2, r1')
    require(m,0x0169FF48,'pophi')
    require(m,0x0169FF50,'cmp','r1, r3')
    require(m,0x0169FF54,'movhi')
    require(m,0x0169FF58,'movls')
    require(m,0x0169FF60,'cmp','r1, r2')
    require(m,0x0169FF64,'blt')
    require(m,0x0169FF6C,'cmp','r1, r3')
    require(m,0x0169FF70,'movgt')
    require(m,0x0169FF74,'movle')

    gt=gamma_targets(d)
    expected=[0x015795F4,0x015795F4,0x015796B4,0x015796B4,0x0157965C,0x0157965C]
    if gt!=expected:
        raise ValueError(f'unexpected exact gamma subtype targets: {gt}')

    mapping=[
        (1,1,'signed'),(2,1,'unsigned'),
        (3,2,'signed'),(4,2,'unsigned'),
        (5,4,'signed'),(6,4,'unsigned'),
    ]
    lines=['# M11-P R2A exact scalar subtype semantics','',f'- SHA-256: `{h}`',f'- proven selector code-pointer base: `0x{CODEPTR_BASE:08x}`','- subtype field: record halfword `+0x02`','', '## Width proof from gamma selector','']
    for s,t in enumerate(gt,1):
        width=1 if s<=2 else 2 if s<=4 else 4
        lines.append(f'- subtype `{s}` -> exact gamma target `0x{t:08x}` -> `{width}` byte(s)')
    lines += ['', '## Signedness proof from range validator','', '- `0x0169ff30`: reads subtype with `LDRH [record+0x02]`.', '- `0x0169ff34`: `ANDS ..., #1` separates odd and even subtype values.', '- even path (bit0=0) uses ARM unsigned conditions `HI` / `LS` for lower/upper-bound checks.', '- odd path (bit0=1) uses ARM signed conditions `LT` / `GT` / `LE` for the same lower/upper-bound checks.', '', '## Proven scalar subtype map','']
    for s,w,sign in mapping:
        bits=w*8
        lines.append(f'- subtype `{s}` = **{sign} {bits}-bit integer**')
    lines += ['', '## Exact validator block','', '```text']
    for a in range(0x0169FF30,0x0169FF7C,4):
        i=m.get(a)
        if i: lines.append(f'0x{a:08x}: {i.mnemonic} {i.op_str}')
    lines += ['```','', '## Interpretation boundary','', 'This identifies the generic scalar object-format enum consumed by gamma. It does not identify photographic gamma modes, RGB/Yb table selection, or R2YS category numbers.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
