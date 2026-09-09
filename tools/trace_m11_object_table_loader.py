#!/usr/bin/env python3
"""Trace Leica M11-P object-table allocation/initialization boundary.

Object table installer 0x0169d184 is directly proven to:
  BL 0x016a4178
  store returned r0 into global 0x433251b0
  tail-branch 0x016a3b28
This pass traces 0x016a4178 and 0x016a3b28, their direct callers/callees, nearby
immediates, and exact-affine printable strings. The goal is to distinguish raw
allocation from record population and identify the function that fills the
0x210 x 0x30-byte object database.
"""
from __future__ import annotations

import argparse, hashlib, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
DATA_BASE=0x3EFD2A98
TARGETS={
    'object_table_alloc_candidate':0x016A4178,
    'post_install_init_candidate':0x016A3B28,
    'object_table_installer':0x0169D184,
}
SCAN_CODE_START=0x01690000
SCAN_CODE_END=0x016B0000


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def next_prologue(d,s,maxlen=0x1800):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(len(d),s+maxlen)
def nearest_prologue(d,c,r=0x1000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(SCAN_CODE_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def direct_callers(d,target):
    out=[]
    for o in range(SCAN_CODE_START,min(SCAN_CODE_END,len(d)-4)&~3,4):
        if bl_target(o,u32(d,o))==target:out.append(o)
    return out
def is_ldr_literal(w):return (w&0x0f7f0000)==0x051f0000
def literal_value(d,off,w):
    if not is_ldr_literal(w):return None
    imm=w&0xfff;p=off+8+(imm if w&0x00800000 else -imm)
    if p<0 or p+4>len(d) or p&3:return None
    return p,u32(d,p)
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def printable(d,raw,maxlen=220):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r')
def string_for_value(d,v):
    raw=(v-DATA_BASE)&0xffffffff
    if raw>=len(d):return None
    s=printable(d,raw)
    return (raw,s) if s else None
def body_rows(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[s:e],s):
        notes=[]
        if i.address+4<=len(d) and not(i.address&3):
            w=u32(d,i.address);bt=bl_target(i.address,w)
            if bt is not None:notes.append(f'BL=0x{bt:08x}')
            lv=literal_value(d,i.address,w)
            if lv:
                pool,v=lv;notes.append(f'lit[0x{pool:08x}]=0x{v:08x}')
                st=string_for_value(d,v)
                if st:notes.append(f'string={st[1]!r}')
        out.append((i,f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"+(" ; "+" ; ".join(notes) if notes else "")))
    return out
def movpair_constants(d,s,e):
    vals=[]
    for o in range(s&~3,min(e,len(d)-4)&~3,4):
        m=mov16(u32(d,o))
        if not m or m[0]!='movw':continue
        _,rd,lo=m
        for p in range(o+4,min(e,o+0x30)+1,4):
            m2=mov16(u32(d,p))
            if m2 and m2[0]=='movt' and m2[1]==rd:
                v=lo|(m2[2]<<16);vals.append((o,p,rd,v,string_for_value(d,v)));break
    return vals
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    lines=['# M11-P R2A object table allocation / initialization trace','',f'- SHA-256: `{h}`','- installer `0x0169d184` stores `0x016a4178` return value into `0x433251b0`, then tail-branches to `0x016a3b28`.','']
    for name,target in TARGETS.items():
        end=next_prologue(d,target);rows=body_rows(d,target,end);calls=Counter()
        for i,_ in rows:
            if i.address+4<=len(d):
                bt=bl_target(i.address,u32(d,i.address))
                if bt is not None:calls[bt]+=1
        callers=direct_callers(d,target);consts=movpair_constants(d,target,end)
        lines += [f'## `{name}` `0x{target:08x}`','',f'- bounded body: `0x{target:08x}–0x{end:08x}` (`0x{end-target:x}` bytes)',f'- direct BL callers in object module: `{len(callers)}`',f'- direct callees: `{len(calls)}`','- direct callers: '+(', '.join(f'`0x{x:08x}`' for x in callers) if callers else 'none')]
        for t,n in calls.most_common():lines.append(f'  - callee `0x{t:08x}`: `{n}` call(s)')
        lines += ['- notable immediate/MOVW+MOVT constants:']
        for a,b,r,v,st in consts:
            extra=f' -> string raw `0x{st[0]:08x}` `{st[1]}`' if st else ''
            lines.append(f'  - `0x{a:08x}`/`0x{b:08x}` r{r}=`0x{v:08x}`{extra}')
        lines += ['','```text'];lines.extend(text for _,text in rows);lines += ['```','']
        if callers:
            lines += ['### Caller windows','']
            for c in callers:
                pro=nearest_prologue(d,c)
                lines.append(f'#### call `0x{c:08x}` / prologue `{("0x%08x"%pro) if pro else "unknown"}`')
                lines += ['```text'];lines.extend(text for _,text in body_rows(d,max(pro or c,c-0x70),c+0x70));lines += ['```','']
    lines += ['## Interpretation boundary','', 'Allocation, zeroing, loading, and record population are assigned only when the traced instructions support them directly. A pointer-returning routine alone is not called an allocator unless its callee/size behavior establishes that role.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
