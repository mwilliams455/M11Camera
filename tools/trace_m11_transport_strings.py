#!/usr/bin/env python3
"""Recover Leica M11-P transport diagnostic strings using the proven data affine.

The data/string affine 0x3efd2a98 was independently reconciled from exact gamma
string xrefs. This pass applies it only to literal/MOVW+MOVT constants used in
transport routines and emits printable strings. Strings can support subsystem
naming more safely than structural inference.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
BASE=0x3EFD2A98
RANGES=[
    ("transport_engine",0x0194A7B0,0x0194ABE0),
    ("preflight",0x0194C01C,0x0194C500),
    ("command_descriptor",0x01949DC4,0x01949F80),
    ("alloc_or_buffer",0x0194CEDC,0x0194D100),
    ("send_path_a",0x0194D3D4,0x0194D468),
    ("send_path_b",0x0194D468,0x0194D674),
]


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def is_ldr_literal(w): return (w & 0x0F7F0000)==0x051F0000
def ldr_literal(d,off,w):
    if not is_ldr_literal(w): return None
    imm=w&0xfff; pool=off+8+(imm if w&0x00800000 else -imm)
    if pool<0 or pool+4>len(d) or pool&3: return None
    return pool,u32(d,pool),(w>>12)&0xf
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000): return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def printable(d,raw,maxlen=240):
    if raw<0 or raw>=len(d): return None
    end=d.find(b'\0',raw,min(len(d),raw+maxlen))
    if end<=raw: return None
    b=d[raw:end]
    if len(b)<4: return None
    try:s=b.decode('ascii')
    except UnicodeDecodeError:return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s): return None
    return s.replace('\n','\\n').replace('\r','\\r')
def ann(d,v):
    raw=(v-BASE)&0xffffffff
    if raw>=len(d): return None
    s=printable(d,raw)
    return (raw,s) if s else None
def scan_range(d,s,e):
    rows=[]; seen=set()
    for off in range(s&~3,min(e,len(d)-4)&~3,4):
        w=u32(d,off); lit=ldr_literal(d,off,w)
        if lit:
            pool,v,rd=lit; a=ann(d,v)
            if a and (v,a[1]) not in seen:
                seen.add((v,a[1])); rows.append((off,'ldr-literal',rd,v,a[0],a[1]))
        m=mov16(w)
        if m and m[0]=='movw':
            _,rd,lo=m
            for p in range(off+4,min(e,off+0x30)+1,4):
                m2=mov16(u32(d,p))
                if m2 and m2[0]=='movt' and m2[1]==rd:
                    v=lo|(m2[2]<<16); a=ann(d,v)
                    if a and (v,a[1]) not in seen:
                        seen.add((v,a[1])); rows.append((off,f'movw/movt@0x{p:08x}',rd,v,a[0],a[1]))
                    break
    return rows
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    lines=['# M11-P R2A transport diagnostic string trace','',f'- SHA-256: `{h}`',f'- exact data/string affine base: `0x{BASE:08x}`','']
    for name,s,e in RANGES:
        rows=scan_range(d,s,e); lines += [f'## `{name}` `0x{s:08x}–0x{e:08x}`','',f'- printable exact-affine constants: `{len(rows)}`']
        for off,kind,rd,v,raw,text in rows:
            lines.append(f'- `0x{off:08x}` {kind} r{rd}=`0x{v:08x}` -> raw `0x{raw:08x}`: `{text}`')
        lines.append('')
    lines += ['## Interpretation boundary','', 'Only exact-affine printable strings are used for naming evidence. Structural behavior without a supporting string remains described neutrally.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
