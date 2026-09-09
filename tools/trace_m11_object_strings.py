#!/usr/bin/env python3
"""Recover diagnostic strings from Leica M11-P object-model routines.

Uses the exact reconciled data/string affine 0x3efd2a98. The target routines are
those directly proven in gamma object lookup/type/subtype/value handling. The
purpose is to recover original terminology for the record fields without
inferring enum meanings from numeric patterns.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
BASE=0x3EFD2A98
RANGES=[
    ("external_id_to_slot",0x0169E7A4,0x0169E850),
    ("major_type_accessor",0x0169E6EC,0x0169E748),
    ("subtype_accessor",0x0169E748,0x0169E7A4),
    ("scalar_value_accessor",0x0169D8FC,0x0169DA28),
    ("element_count_accessor",0x0169D618,0x0169D700),
    ("element_accessor",0x0169DD00,0x0169DE40),
    ("element_filter",0x016A0CB0,0x016A0E20),
    ("payload_type2_accessors",0x0169E0E8,0x0169E260),
]

def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def is_ldr(w): return (w&0x0f7f0000)==0x051f0000
def lit(d,o,w):
    if not is_ldr(w): return None
    imm=w&0xfff; p=o+8+(imm if w&0x00800000 else -imm)
    if p<0 or p+4>len(d) or p&3:return None
    return p,u32(d,p),(w>>12)&0xf
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def printable(d,r,maxlen=220):
    if r<0 or r>=len(d):return None
    e=d.find(b'\0',r,min(len(d),r+maxlen))
    if e<=r:return None
    b=d[r:e]
    if len(b)<4:return None
    try:s=b.decode('ascii')
    except: return None
    if any((ord(c)<32 and c not in '\r\n\t') or ord(c)>=127 for c in s):return None
    return s.replace('\n','\\n').replace('\r','\\r')
def ann(d,v):
    r=(v-BASE)&0xffffffff
    if r>=len(d):return None
    s=printable(d,r)
    return (r,s) if s else None
def scan(d,s,e):
    out=[];seen=set()
    for o in range(s&~3,min(e,len(d)-4)&~3,4):
        w=u32(d,o); q=lit(d,o,w)
        if q:
            _,v,rd=q;a=ann(d,v)
            if a and (v,a[1]) not in seen:
                seen.add((v,a[1]));out.append((o,'literal',rd,v,a[0],a[1]))
        m=mov16(w)
        if m and m[0]=='movw':
            _,rd,lo=m
            for p in range(o+4,min(e,o+0x30)+1,4):
                m2=mov16(u32(d,p))
                if m2 and m2[0]=='movt' and m2[1]==rd:
                    v=lo|(m2[2]<<16);a=ann(d,v)
                    if a and (v,a[1]) not in seen:
                        seen.add((v,a[1]));out.append((o,f'movpair@0x{p:08x}',rd,v,a[0],a[1]))
                    break
    return out
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    lines=['# M11-P R2A object-model diagnostic string trace','',f'- SHA-256: `{h}`',f'- exact data/string affine: `0x{BASE:08x}`','']
    for n,s,e in RANGES:
        rows=scan(d,s,e);lines += [f'## `{n}` `0x{s:08x}–0x{e:08x}`','',f'- printable constants: `{len(rows)}`']
        for o,k,rd,v,r,text in rows:lines.append(f'- `0x{o:08x}` {k} r{rd}=`0x{v:08x}` -> raw `0x{r:08x}`: `{text}`')
        lines.append('')
    lines += ['## Interpretation boundary','', 'Only exact-affine printable strings are terminology evidence. Numeric enum meanings remain unresolved when strings do not name them.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
