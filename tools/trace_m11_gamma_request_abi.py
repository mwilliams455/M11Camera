#!/usr/bin/env python3
"""Prove Leica M11-P BB060014 -> gamma-main request ABI and payload sizing.

The master dispatcher case for incoming BB060014 reconstructs a 16-byte prefix
from request words, copies 249 bytes from request+0x10, and appends its first
argument at a synthetic trailer. Gamma-main uses that trailer as a request
byte-count/extent: it rejects <=10, subtracts the 11-byte fixed prefix, and
requires the remainder to match the scalar payload width.

Gamma operation semantics are independently proven by
trace_m11_gamma_object_access_semantics.py:
  1 = WRITE/SET
  2 = READ/GET
Operation 3 is reported only structurally as the serializer/bulk-return branch.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
DISP_START=0x0157BC84
DISP_END=0x0157BCC0
UP_START=0x0157BFC8
UP_END=0x0157C000
GAMMA_START=0x01579338
GAMMA_END=0x01579BF4
LOOKUP=0x0169E7A4
SERIALIZER=0x015A6374


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def imap(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    return {i.address:i for i in md.disasm(d[s:e],s)}
def req(m,a,mn,contains=None,exact=None):
    i=m.get(a)
    good=i is not None and i.mnemonic==mn
    if contains is not None:good=good and contains in i.op_str
    if exact is not None:good=good and i.op_str==exact
    if not good:
        got='missing' if i is None else f'{i.mnemonic} {i.op_str}'
        want=exact if exact is not None else contains or ''
        raise ValueError(f'{a:#x}: expected {mn} {want}; got {got}')
    return i

def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    dm=imap(d,DISP_START,DISP_END);um=imap(d,UP_START,UP_END);gm=imap(d,GAMMA_START,GAMMA_END)

    # Upstream receive-object pairing: +0x1c is the BB06 payload pointer and
    # +0x18 becomes dispatcher arg0. Gamma behavior below proves arg0 is the
    # valid request byte count/extent used for payload-length validation.
    req(um,0x0157BFCC,'ldr',exact='r1, [r0, #0x1c]')
    req(um,0x0157BFF4,'ldr',exact='r0, [r0, #0x18]')
    if bl_target(0x0157BFF8,u32(d,0x0157BFF8))!=0x0157BB14:raise ValueError('master dispatcher caller changed')

    # Dispatcher marshalling.
    req(dm,0x0157BC84,'ldr',exact='r7, [r1]')
    req(dm,0x0157BC88,'mov',exact='ip, r0')
    req(dm,0x0157BC8C,'ldr',exact='r6, [r4, #4]')
    req(dm,0x0157BC94,'ldr',exact='r5, [r4, #8]')
    req(dm,0x0157BC9C,'ldr',exact='r4, [r4, #0xc]')
    req(dm,0x0157BC98,'mov',exact='r2, #0xf9')
    req(dm,0x0157BC90,'add',exact='r1, r1, #0x10')
    req(dm,0x0157BCA0,'mov',exact='r0, sp')
    req(dm,0x0157BCA4,'str',contains='[sp, #0xfc]')
    if bl_target(0x0157BCBC,u32(d,0x0157BCBC))!=GAMMA_START:raise ValueError('gamma call target changed')

    # Gamma register normalization and exact field loads.
    req(gm,0x01579338,'sub',exact='sp, sp, #0x10')
    req(gm,0x0157933C,'push')
    req(gm,0x01579340,'sub',exact='sp, sp, #0x244')
    req(gm,0x01579344,'add',exact='ip, sp, #0x264')
    req(gm,0x0157934C,'stmib',contains='{r0, r1, r2, r3}')
    req(gm,0x01579348,'ldr',exact='r4, [sp, #0x374]')
    req(gm,0x01579364,'cmp',exact='r4, #0xa')
    req(gm,0x01579374,'ldr',exact='r6, [sp, #0x26c]')
    req(gm,0x0157937C,'ldrb',exact='r7, [sp, #0x270]')
    req(gm,0x01579384,'ldrh',contains='[r3, #1]')
    req(gm,0x015793A4,'strh',contains='[r1]')
    req(gm,0x015793C4,'sub',exact='r4, r4, #0xb')
    req(gm,0x015793CC,'uxth',exact='r4, r4')
    req(gm,0x015793B0,'mov',exact='r0, r6')
    if bl_target(0x015793B4,u32(d,0x015793B4))!=LOOKUP:raise ValueError('object lookup target changed')

    # Scalar payload-size checks and exact payload start at normalized +0x0b.
    req(gm,0x015795F4,'cmp',exact='r4, #1')
    req(gm,0x015795F8,'ldrbeq',exact='r3, [sp, #0x273]')
    req(gm,0x015796B4,'cmp',exact='r4, #2')
    req(gm,0x015796BC,'ldrb',exact='r2, [sp, #0x274]')
    req(gm,0x015796C0,'ldrb',exact='r3, [sp, #0x273]')
    req(gm,0x0157965C,'cmp',exact='r4, #4')
    for a in (0x01579664,0x01579668,0x01579670,0x01579678):
        req(gm,a,'ldrb')

    # Operation selection and operation-3 serializer branch.
    req(gm,0x01579540,'cmp',exact='r7, #1')
    req(gm,0x01579548,'cmp',exact='r7, #3')
    req(gm,0x01579570,'cmp',exact='r7, #2')
    if bl_target(0x015798E8,u32(d,0x015798E8))!=SERIALIZER:raise ValueError('operation-3 serializer target changed')
    req(gm,0x015798F0,'mov',exact='r3, #0x1a')
    req(gm,0x015798F8,'movt',exact='r3, #0xbb06')
    req(gm,0x01579900,'mov',exact='ip, #3')

    # +0x09 halfword is copied into the simple response before any processing.
    # For op1/op2 paths, r8 is subsequently overwritten on all fp<=1/fp>1
    # outcomes at 0x159420/0x159424 before later control tests. Op3 echoes r8
    # into its BB06001A response at +0x09. No object accessor receives r8.
    req(gm,0x01579420,'movhi',exact='r8, #0')
    req(gm,0x01579424,'andls',exact='r8, r3, #1')
    req(gm,0x0157990C,'strh',exact='r8, [sp, #0x29]')

    frame=0x278
    def rec_off(stack_off):return stack_off-0x268
    fields=[
        ('command',0x00,'incoming `BB060014`'),
        ('external object ID',0x04,'passed unchanged to `0x0169e7a4`'),
        ('operation',0x08,'`1=WRITE/SET`, `2=READ/GET`; `3` selects structured serializer/bulk-return path'),
        ('echoed 16-bit request tag',0x09,'copied to response `+0x09`; not passed to object accessors'),
        ('typed payload',0x0B,'SET payload begins here; exact width is 1/2/4 bytes for scalar subtypes'),
        ('copied continuation',0x10,'249 bytes copied from incoming request+0x10 into caller scratch'),
        ('synthetic request byte-count/extent trailer',0x10C,'upstream object `+0x18` -> dispatcher arg0 -> caller `[sp+0xfc]`; gamma validates fixed-prefix/payload length from it'),
    ]

    lines=['# M11-P R2A exact gamma request ABI','',f'- SHA-256: `{h}`','- incoming command: `BB060014` (master-dispatch case 19)','- callable gamma entry: `0x01579338`','- generic object lookup: `0x0169e7a4`','- fixed request prefix before typed payload: **11 bytes**','- proven operations: **1 = WRITE/SET; 2 = READ/GET**','', '## Proven normalized request layout','', '| offset | field | proof/use |','|---:|---|---|']
    for name,off,p in fields:lines.append(f'| `+0x{off:03x}` | {name} | {p} |')

    lines += ['', '## Request-length proof','',
        '- The upstream receive object supplies dispatcher `r0` from object `+0x18`; its BB06 payload pointer is object `+0x1c`.',
        '- The dispatcher preserves that `r0` at caller scratch `+0xfc`; gamma reloads it as `r4`.',
        '- Gamma rejects `r4 <= 10`, then executes `sub r4, r4, #0xb`.',
        '- The resulting value must equal `1`, `2`, or `4` on the corresponding scalar SET payload-width paths.',
        '- Therefore this value is the valid request byte count/extent and the gamma fixed prefix is exactly **11 bytes**.',
        '', '## Stack arithmetic proof','',
        '- Let `S` be SP on entry to `0x01579338`.',
        '- `sub sp,#0x10` + 9-register push (`0x24`) + local `0x244` gives working `SP = S - 0x278`.',
        '- `stmib (SP+0x264), {r0-r3}` writes at `S-0x10 .. S-0x04`, creating the 16-byte prefix immediately before the copied caller scratch.',
        '- Therefore normalized prefix base is `S-0x10` and working-stack offset maps to normalized offset `stack_offset - 0x268`.',
        f'- `[SP+0x26c]` -> `+0x{rec_off(0x26c):x}` = external object ID.',
        f'- `[SP+0x270]` -> `+0x{rec_off(0x270):x}` = operation byte.',
        f'- `[SP+0x273]` -> `+0x{rec_off(0x273):x}` = first typed-payload byte.',
        f'- `[SP+0x374]` -> `+0x{rec_off(0x374):x}` = synthetic request byte-count/extent trailer.',
        '', '## Exact external-object-ID chain','',
        '`request + 0x04` -> dispatcher `r6` -> gamma `[SP+0x26c]` -> `r6` -> `r0` -> `BL 0x0169e7a4`.',
        '', '## Echo-tag boundary','',
        'The request halfword at `+0x09` is preserved into the simple response at response `+0x09`. Operation 3 likewise writes it to `BB06001A +0x09`. On operation-1/2 control paths, the working `r8` register is overwritten before later object-control decisions, and no object accessor receives the original halfword. The safe semantic name is therefore **echoed request tag**; no stronger label such as sequence number is assigned.',
        '', '## Interpretation boundary','',
        'Operation 3 is proven to enter the structured serializer and emit `BB06001A`, but its API name remains unassigned. The ABI still does not enumerate which external object IDs are used for gamma; that requires runtime request capture or producer evidence from the other side of the receive boundary.','']
    return '\n'.join(lines)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
