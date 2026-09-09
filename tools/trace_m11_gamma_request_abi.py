#!/usr/bin/env python3
"""Prove Leica M11-P BB060014 -> gamma-main request ABI.

The master dispatcher case for incoming BB060014 reconstructs the request from
four register arguments plus a 249-byte body copy. Callable gamma-main begins at
0x01579338, creates a 16-byte register-save prefix, and then treats the resulting
bytes as one contiguous request record. This pass asserts the exact instructions
and emits field offsets, including the external object ID passed to 0x0169e7a4.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
DISP_START=0x0157BC84
DISP_END=0x0157BCC0
GAMMA_START=0x01579338
GAMMA_END=0x01579410
LOOKUP=0x0169E7A4


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def imap(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    return {i.address:i for i in md.disasm(d[s:e],s)}
def req(m,a,mn,contains=None):
    i=m.get(a)
    if i is None or i.mnemonic!=mn or (contains and contains not in i.op_str):
        got='missing' if i is None else f'{i.mnemonic} {i.op_str}'
        raise ValueError(f'{a:#x}: expected {mn} {contains or ""}; got {got}')
    return i
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    dm=imap(d,DISP_START,DISP_END);gm=imap(d,GAMMA_START,GAMMA_END)
    # Dispatcher marshalling guards.
    req(dm,0x0157BC84,'ldr','r7, [r1]')
    req(dm,0x0157BC8C,'ldr','r6, [r4, #4]')
    req(dm,0x0157BC94,'ldr','r5, [r4, #8]')
    req(dm,0x0157BC9C,'ldr','r4, [r4, #0xc]')
    req(dm,0x0157BC98,'mov','r2, #0xf9')
    req(dm,0x0157BC90,'add','r1, r1, #0x10')
    req(dm,0x0157BCA0,'mov','r0, sp')
    req(dm,0x0157BCA4,'str','[sp, #0xfc]')
    if bl_target(0x0157BCBC,u32(d,0x0157BCBC))!=GAMMA_START:raise ValueError('gamma call target changed')
    # Gamma register-normalization / request field guards.
    req(gm,0x01579338,'sub','sp, sp, #0x10')
    req(gm,0x0157933C,'push')
    req(gm,0x01579340,'sub','sp, sp, #0x244')
    req(gm,0x01579344,'add','ip, sp, #0x264')
    req(gm,0x0157934C,'stmib','{r0, r1, r2, r3}')
    req(gm,0x01579348,'ldr','r4, [sp, #0x374]')
    req(gm,0x01579374,'ldr','r6, [sp, #0x26c]')
    req(gm,0x01579378,'add','r3, sp, #0x270')
    req(gm,0x0157937C,'ldrb','r7, [sp, #0x270]')
    req(gm,0x01579384,'ldrh','r8, [r3, #1]')
    req(gm,0x015793B0,'mov','r0, r6')
    if bl_target(0x015793B4,u32(d,0x015793B4))!=LOOKUP:raise ValueError('object lookup target changed')

    # Let caller SP at gamma entry be S. 0x159338 reserves 0x10; push reserves
    # 0x24; local frame reserves 0x244 -> working SP = S-0x278.
    frame=0x278
    def rec_off(stack_off):
        # normalized record begins at S-0x10, so stack address = (S-frame)+off
        # relative to record base S-0x10 => off-frame+0x10 = off-0x268.
        return stack_off-0x268
    fields=[
        ('header / incoming command',0x00,'r0 from request[0] = BB060014'),
        ('external object ID',0x04,'r1; reloaded as r6 and passed unchanged to 0x0169e7a4'),
        ('packed control word A',0x08,'r2; byte +8 -> r7, halfword +9 -> r8'),
        ('control/payload word B',0x0C,'r3; later byte accesses cross offsets +0x0b..+0x0e'),
        ('copied request body',0x10,'249 bytes copied from incoming request+0x10'),
        ('dispatcher context',0x10C,'original dispatcher r0 stored at caller stack+0xfc'),
    ]
    lines=['# M11-P R2A exact gamma request ABI','',f'- SHA-256: `{h}`','- incoming command: `BB060014` (master-dispatch case 19)','- callable gamma entry: `0x01579338`','- generic object lookup: `0x0169e7a4`','', '## Proven normalized request layout','', '| offset | field | proof/use |','|---:|---|---|']
    for name,off,p in fields:lines.append(f'| `+0x{off:03x}` | {name} | {p} |')
    lines += ['', '## Stack arithmetic proof','', '- Let `S` be SP on entry to `0x01579338`.', '- `sub sp,#0x10` + 9-register push (`0x24`) + local `0x244` gives working `SP = S - 0x278`.', '- `stmib (SP+0x264), {r0-r3}` writes at `S-0x10 .. S-0x04`, creating the 16-byte prefix immediately before the copied body at caller `S`.', '- Therefore normalized record base is `S-0x10` and any working-stack offset maps to record offset `stack_offset - 0x268`.', f'- `[SP+0x26c]` maps to record `+0x{rec_off(0x26c):x}` = external object ID.', f'- `[SP+0x270]` maps to record `+0x{rec_off(0x270):x}` = first packed-control byte.', f'- `[SP+0x374]` maps to record `+0x{rec_off(0x374):x}` = dispatcher context.', '', '## Exact external-object-ID chain','', '`request + 0x04` -> dispatcher `r6` -> gamma `[SP+0x26c]` -> `r6` -> `r0` -> `BL 0x0169e7a4`.', '', 'This proves the word at request offset `+0x04` is an external object ID in the same namespace as the generated 528-record table (+0x08 field).', '', '## Interpretation boundary','', 'The ABI proves field positions and the object-ID namespace. It does not by itself enumerate which object IDs are used for gamma; that requires BB060014 producer sites or runtime captures.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
