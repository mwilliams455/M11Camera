#!/usr/bin/env python3
"""Trace Leica M11-P consumers/registrations of gamma packet entrypoints.

Primary targets are the exact Leica gamma callable/adjacent families:
  0x01579338 -- true callable gamma-main entry (directly called by 0x0157bcbc)
  0x01579bf8 -- adjacent gamma-invalid / BB060017 family
The independently proven code-pointer affine 0x3faa87d0 lets us search for
translated function pointers in data/dispatch tables in addition to direct A32
BL callers. This is Leica-primary consumer evidence; no public source names are
assigned.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CODEPTR_BASE=0x3FAA87D0
DATA_BASE=0x3EFD2A98
TARGETS={
    'gamma_main_callable':0x01579338,
    'gamma_invalid':0x01579BF8,
}
SCAN_CODE_START=0x01000000
SCAN_CODE_END=0x02000000


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,c,r=0x1400):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(SCAN_CODE_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def next_prologue(d,s,maxlen=0x1800):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(SCAN_CODE_END,len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(SCAN_CODE_END,len(d),s+maxlen)
def direct_callers(d,target):
    return [o for o in range(SCAN_CODE_START,min(SCAN_CODE_END,len(d)-4)&~3,4) if bl_target(o,u32(d,o))==target]
def all_word_hits(d,value):
    needle=struct.pack('<I',value&0xffffffff);out=[];p=0
    while True:
        p=d.find(needle,p)
        if p<0:break
        if not(p&3):out.append(p)
        p+=1
    return out
def printable(d,raw,maxlen=160):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r')
def disasm(d,s,e,limit=180):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for n,i in enumerate(md.disasm(d[max(0,s):min(len(d),e)],max(0,s))):
        if n>=limit:break
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:note=f' ; BL=0x{bt:08x}'
        out.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    return out
def pointer_context(d,off,radius_words=8):
    rows=[]
    s=max(0,off-radius_words*4)&~3;e=min(len(d)-4,off+(radius_words+1)*4)&~3
    for p in range(s,e+1,4):
        v=u32(d,p);ann=''
        code=(v-CODEPTR_BASE)&0xffffffff
        if SCAN_CODE_START<=code<SCAN_CODE_END:ann+=f' -> code_raw 0x{code:08x}'
        raw=(v-DATA_BASE)&0xffffffff
        if raw<len(d):
            txt=printable(d,raw)
            if txt:ann+=f' -> string_raw 0x{raw:08x} {txt!r}'
        rows.append(f'0x{p:08x}: 0x{v:08x}{ann}')
    return rows
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    lines=['# M11-P R2A gamma entry consumer / registration trace','',f'- SHA-256: `{h}`',f'- proven code-pointer affine: `0x{CODEPTR_BASE:08x}`','- gamma main callable entry corrected to `0x01579338` from a direct higher-level BL at `0x0157bcbc`.','']
    for name,target in TARGETS.items():
        ptr=(target+CODEPTR_BASE)&0xffffffff;calls=direct_callers(d,target);ph=all_word_hits(d,ptr);rawhits=all_word_hits(d,target)
        lines += [f'## `{name}` raw `0x{target:08x}`','',f'- translated code pointer: `0x{ptr:08x}`',f'- direct A32 BL callers: `{len(calls)}`',f'- exact translated-pointer words in full image: `{len(ph)}`',f'- raw-offset word occurrences in full image: `{len(rawhits)}`','']
        if calls:
            lines += ['### Direct caller families','']
            for c in calls:
                pro=nearest_prologue(d,c);end=next_prologue(d,pro) if pro else c+0x80
                lines.append(f'- call `0x{c:08x}` / prologue `{("0x%08x"%pro) if pro else "unknown"}` / bound `{("0x%08x"%end) if end else "unknown"}`')
                lines += ['```text'];lines.extend(disasm(d,max(pro or c,c-0xc0),min(end,c+0x90),150));lines += ['```','']
        if ph:
            lines += ['### Translated code-pointer contexts','']
            for off in ph[:80]:
                lines.append(f'#### pointer word at raw `0x{off:08x}`')
                lines += ['```text'];lines.extend(pointer_context(d,off));lines += ['```','']
        if rawhits:
            lines += ['### Raw-offset word contexts','']
            for off in rawhits[:40]:
                lines.append(f'#### raw-offset word at `0x{off:08x}`')
                lines += ['```text'];lines.extend(pointer_context(d,off));lines += ['```','']
    lines += ['## Interpretation boundary','', 'A translated code-pointer occurrence is strong evidence of a registration/dispatch reference because the code-pointer affine is independently proven. Semantic category assignment still requires surrounding descriptor fields, caller behavior, or explicit diagnostics.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
