#!/usr/bin/env python3
"""Trace upstream callers/registration of Leica M11-P BB06 R2Y dispatcher.

The exact dispatcher at 0x0157bb14 accepts BB060001..BB060024 and routes
BB060014 to gamma main. No static BB060014 producer exists in the image. This
pass finds direct BL callers plus exact translated-code-pointer references to
the dispatcher, then traces the enclosing caller bodies to identify whether the
boundary is a receive/demux/transport callback.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TARGET=0x0157BB14
CODEPTR_BASE=0x3FAA87D0
DATA_BASE=0x3EFD2A98
CODE_START=0x01000000
CODE_END=0x02000000

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,c,r=0x2000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(CODE_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def next_prologue(d,s,maxlen=0x3000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(CODE_END,len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(CODE_END,len(d),s+maxlen)
def direct_callers(d):
    return [o for o in range(CODE_START,min(CODE_END,len(d)-4)&~3,4) if bl_target(o,u32(d,o))==TARGET]
def word_hits(d,v):
    n=struct.pack('<I',v&0xffffffff);out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:break
        if not(p&3):out.append(p)
        p+=1
    return out
def printable(d,raw,maxlen=200):
    if raw<0 or raw>=len(d):return None
    e=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if e<=raw:return None
    b=d[raw:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r')
def disasm(d,s,e,limit=1200):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for n,i in enumerate(md.disasm(d[s:e],s)):
        if n>=limit:break
        notes=[]
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:notes.append(f'BL=0x{bt:08x}')
        out.append((i,f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'+((' ; '+' ; '.join(notes)) if notes else '')))
    return out
def ptr_context(d,off,n=12):
    rows=[]
    for p in range(max(0,off-n*4)&~3,min(len(d)-4,off+n*4)+1,4):
        v=u32(d,p);ann=[]
        code=(v-CODEPTR_BASE)&0xffffffff
        if CODE_START<=code<CODE_END:ann.append(f'code_raw=0x{code:08x}')
        raw=(v-DATA_BASE)&0xffffffff
        if raw<len(d):
            s=printable(d,raw)
            if s:ann.append(f'string={s!r}')
        rows.append(f'0x{p:08x}: 0x{v:08x}'+((' ; '+' ; '.join(ann)) if ann else ''))
    return rows
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    callers=direct_callers(d);ptr=(TARGET+CODEPTR_BASE)&0xffffffff;ph=word_hits(d,ptr);rh=word_hits(d,TARGET)
    lines=['# M11-P R2A BB06 master-dispatch upstream trace','',f'- SHA-256: `{h}`',f'- dispatcher: `0x{TARGET:08x}`',f'- translated pointer: `0x{ptr:08x}`',f'- direct BL callers: `{len(callers)}`',f'- translated-pointer hits: `{len(ph)}`',f'- raw-offset word hits: `{len(rh)}`','']
    for c in callers:
        pro=nearest_prologue(d,c);end=next_prologue(d,pro) if pro else c+0x300;rows=disasm(d,pro or max(CODE_START,c-0x100),end)
        lines += [f'## direct call `0x{c:08x}`','',f'- prologue: `{("0x%08x"%pro) if pro else "unknown"}`',f'- bound: `0x{end:08x}`','- direct callees in body:']
        seen=[]
        for i,_ in rows:
            bt=bl_target(i.address,u32(d,i.address)) if i.address+4<=len(d) else None
            if bt is not None and bt not in seen:seen.append(bt)
        for t in seen:lines.append(f'  - `0x{t:08x}`')
        lines += ['','```text'];lines.extend(x for _,x in rows);lines += ['```','']
    if ph:
        lines += ['## translated-pointer contexts','']
        for p in ph:
            lines += [f'### raw `0x{p:08x}`','```text'];lines.extend(ptr_context(d,p));lines += ['```','']
    if rh:
        lines += ['## raw-offset contexts','']
        for p in rh:
            lines += [f'### raw `0x{p:08x}`','```text'];lines.extend(ptr_context(d,p));lines += ['```','']
    lines += ['## Interpretation boundary','', 'If the dispatcher appears only behind a receive/demux callback or a translated registration pointer, that supports a receiver-side boundary. No specific IPC/mailbox name is assigned without direct diagnostics or device semantics.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
