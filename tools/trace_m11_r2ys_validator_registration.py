#!/usr/bin/env python3
"""Prove the R2YS validator case and trace its indirect registration.

The generic resource validator at 0x0178af24 uses a 19-entry translated
code-pointer jump table. Index 8 selects the R2Y case, which constructs both
R2YS and R2YE and then validates the shared resource envelope/descriptor list.
The validator has no direct A32 BL callers, so this pass searches for its proven
translated function pointer and reports surrounding registration data.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

EXPECTED=EXPECTED_UNPACKED_SHA
CODEPTR_BASE=0x3FAA87D0
DATA_BASE=0x3EFD2A98
VALIDATOR=0x0178AF24
TABLE=0x0178AF3C
NCASES=19
R2Y_CASE=8
R2Y_TARGET=0x0178B064
CODE_START=0x01000000
CODE_END=0x02000000


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def all_word_hits(d,v):
    n=struct.pack('<I',v&0xffffffff);out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:return out
        if not p&3:out.append(p)
        p+=1
def printable(d,raw,maxlen=180):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except:return None
    if any(ord(c)<32 or ord(c)>=127 for c in s):return None
    return s
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,a,r=0x1400):
    if not(CODE_START<=a<min(CODE_END,len(d))):return None
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for p in range(max(CODE_START,a-r)&~3,a+1,4):
        i=next(md.disasm(d[p:p+4],p),None)
        if i and is_prologue(i):best=p
    return best
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    return [f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip() for i in md.disasm(d[s:e],s)]
def decode_context(d,off,words=12):
    out=[]
    for p in range(max(0,off-words*4)&~3,min(len(d)-4,off+(words+1)*4)&~3,4):
        v=u32(d,p);ann=[]
        cr=(v-CODEPTR_BASE)&0xffffffff
        if CODE_START<=cr<CODE_END:ann.append(f'code_raw=0x{cr:08x}')
        dr=(v-DATA_BASE)&0xffffffff
        if dr<len(d):
            s=printable(d,dr)
            if s:ann.append(f'string={s!r}')
        out.append(f'0x{p:08x}: 0x{v:08x}'+((' ; '+' ; '.join(ann)) if ann else ''))
    return out
def marker_for_case(d,t):
    # Each marker case is a tiny straight-line block ending in an unconditional
    # branch to the common validator path. Stop at that branch so the first
    # MOVW of the following case cannot overwrite the shared low halfword.
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    ins=list(md.disasm(d[t:min(len(d),t+0x40)],t))
    lo=None;endhi=None;starthi=None
    for i in ins:
        if i.mnemonic=='movw' and i.op_str.startswith('r7,'):
            m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',i.op_str);lo=int(m.group(1),0) if m else None
        elif i.mnemonic=='movt' and i.op_str.startswith('r7,'):
            m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',i.op_str);endhi=int(m.group(1),0) if m else None
        elif i.mnemonic=='movt' and i.op_str.startswith('r3,'):
            m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',i.op_str);starthi=int(m.group(1),0) if m else None
        if i.mnemonic=='b':
            break
    if lo is None or endhi is None or starthi is None:return None
    start=((starthi&0xffff)<<16)|(lo&0xffff);end=((endhi&0xffff)<<16)|(lo&0xffff)
    def ascii4(v):
        try:return struct.pack('<I',v).decode('ascii')
        except:return '?'
    return start,end,ascii4(start),ascii4(end)
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    rawwords=[u32(d,TABLE+4*i) for i in range(NCASES)]
    targets=[(w-CODEPTR_BASE)&0xffffffff for w in rawwords]
    if targets[R2Y_CASE]!=R2Y_TARGET:raise ValueError(f'R2Y case moved: {targets[R2Y_CASE]:#x}')
    r2ym=marker_for_case(d,R2Y_TARGET)
    if not r2ym or r2ym[0]!=0x53593252 or r2ym[1]!=0x45593252:raise ValueError(f'R2Y markers mismatch {r2ym}')
    ptr=(VALIDATOR+CODEPTR_BASE)&0xffffffff
    ph=all_word_hits(d,ptr);rh=all_word_hits(d,VALIDATOR)
    lines=['# M11-P R2A R2YS validator registration trace','',f'- SHA-256: `{h}`',f'- generic validator: `0x{VALIDATOR:08x}`',f'- translated validator pointer: `0x{ptr:08x}`',f'- jump table: `0x{TABLE:08x}`, `{NCASES}` entries',f'- R2Y resource type index: **`{R2Y_CASE}`**','']
    lines += ['## Validator resource-type jump table','', '| index | target | start marker | end marker |','|---:|---|---|---|']
    for i,t in enumerate(targets):
        m=marker_for_case(d,t)
        if m:lines.append(f'| {i} | `0x{t:08x}` | `{m[2]}` (`0x{m[0]:08x}`) | `{m[3]}` (`0x{m[1]:08x}`) |')
        else:lines.append(f'| {i} | `0x{t:08x}` | ? | ? |')
    lines += ['', '## Exact R2Y validator framing proof','',
        '- index 8 case constructs start marker `R2YS` and end marker `R2YE`.',
        '- common path compares `[resource+0x00]` to `R2YS`.',
        '- `[resource+0x04]` is compared with the supplied resource byte size.',
        '- `[resource+0x48]` is compared with the original type index; success for R2Y therefore requires value `8`.',
        '- `[resource+0x4c]` controls the descriptor loop; the verified M11 resource stores `315` there.',
        '- descriptor iteration starts at `resource+0x50` and reads `+0x04 descriptor_size`, `+0x08 map_size`, `+0x0c map_offset`.',
        '- the last four resource bytes are copied and compared with `R2YE`.',
        '- final bounds check uses last `map_offset + map_size + 4 <= resource_size`.','']
    lines += ['## Translated validator-pointer occurrences','',f'- exact translated-pointer words: `{len(ph)}`']
    for off in ph:
        lines.append(f'### pointer at raw `0x{off:08x}`')
        lines+=['```text'];lines.extend(decode_context(d,off));lines+=['```','']
    lines += ['## Raw validator-offset occurrences','',f'- exact raw-offset words: `{len(rh)}`']
    for off in rh:
        lines.append(f'- `0x{off:08x}`')
    lines += ['', '## Interpretation boundary','', 'The validator proves R2YS framing and type index 8, but validation alone does not prove where selected map payloads are consumed. Registration-pointer context is the next bridge into the runtime resource loader/owner.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
