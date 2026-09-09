#!/usr/bin/env python3
"""Trace the Leica M11-P function that constructs the literal R2YE marker.

The dynamic parser candidate scan found one exact A32 MOVW/MOVT construction of
`R2YE` (0x45593252) at 0x0178b064..0x0178b06c, inside prologue 0x0178af24.
This pass treats that as the primary code-side anchor to the embedded R2YS
resource envelope and reports its full function, direct callers, call targets,
constant constructions, and exact-affine printable strings.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

EXPECTED=EXPECTED_UNPACKED_SHA
START=0x0178AF24
CODE_START=0x01000000
CODE_END=0x02000000
DATA_BASE=0x3EFD2A98
R2YS=0x53593252
R2YE=0x45593252


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def find_end(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for p in range(START+4,min(len(d),START+0x4000,CODE_END),4):
        i=next(md.disasm(d[p:p+4],p),None)
        if i and is_prologue(i):return p
    return START+0x2000
def printable(d,raw,maxlen=220):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except:return None
    if any(ord(c)<32 or ord(c)>=127 for c in s):return None
    return s
def direct_callers(d,target):
    out=[]
    for p in range(CODE_START,min(CODE_END,len(d)-4),4):
        if bl_target(p,u32(d,p))==target:out.append(p)
    return out
def nearest_prologue(d,a,r=0x1400):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for p in range(max(CODE_START,a-r)&~3,a+1,4):
        i=next(md.disasm(d[p:p+4],p),None)
        if i and is_prologue(i):best=p
    return best
def immv(op):
    m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',op)
    return int(m.group(1),0) if m else None
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    end=find_end(d)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    ins=list(md.disasm(d[START:end],START))
    calls=[];consts=[];recent={}
    for n,i in enumerate(ins):
        if i.address+4<=len(d):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:calls.append((i.address,bt))
        if i.mnemonic=='movw':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2:
                v=immv(i.op_str)
                if v is not None:recent[p[0]]=(n,i.address,v&0xffff)
        elif i.mnemonic=='movt':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2 and p[0] in recent:
                k,a,lo=recent[p[0]];hi=immv(i.op_str)
                if hi is not None and n-k<=12:
                    v=((hi&0xffff)<<16)|lo;consts.append((a,i.address,p[0],v))
    callers=direct_callers(d,START)
    lines=['# M11-P R2A R2YS/R2YE marker-parser trace','',f'- SHA-256: `{h}`',f'- anchored prologue: `0x{START:08x}`',f'- next prologue/function bound: `0x{end:08x}`',f'- function size: `0x{end-START:x}`',f'- direct A32 callers: `{len(callers)}`','']
    if callers:
        lines += ['## Direct callers','']
        for a in callers:lines.append(f'- `0x{a:08x}`; caller prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
    lines += ['', '## Constructed constants','']
    for a,b,r,v in consts:
        ann=[]
        if v==R2YS:ann.append('**R2YS**')
        if v==R2YE:ann.append('**R2YE**')
        raw=(v-DATA_BASE)&0xffffffff
        s=printable(d,raw) if raw<len(d) else None
        if s:ann.append(f'string raw 0x{raw:08x} `{s}`')
        if v<len(d):
            s2=printable(d,v)
            if s2:ann.append(f'raw string `{s2}`')
        lines.append(f'- `0x{a:08x}`..`0x{b:08x}` `{r}` = `0x{v:08x}`'+((' — '+'; '.join(ann)) if ann else ''))
    lines += ['', '## Direct calls','']
    for a,t in calls:lines.append(f'- `0x{a:08x}` -> `0x{t:08x}`')
    lines += ['', '## Full anchored function','```text']
    for i in ins:
        note=''
        bt=bl_target(i.address,u32(d,i.address)) if i.address+4<=len(d) else None
        if bt is not None:note=f' ; BL=0x{bt:08x}'
        lines.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    lines += ['```','', '## R2YE dataflow slices','']
    # Emit contexts around any instruction mentioning r7 after the exact marker construction.
    marker_idx=next((n for n,(a,b,r,v) in enumerate(consts) if v==R2YE),None)
    for i in ins:
        if 0x0178B060<=i.address<=min(end,0x0178B200) and ('r7' in i.op_str or i.address in (0x0178B064,0x0178B068,0x0178B06C)):
            lines.append(f'- `0x{i.address:08x}: {i.mnemonic} {i.op_str}`')
    lines += ['', '## Interpretation boundary','', 'The exact R2YE construction ties this function to the R2Y resource envelope only if the constructed value participates in comparison/validation against input-derived bytes or words. The function is not named as the descriptor parser until that dataflow is visible.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
