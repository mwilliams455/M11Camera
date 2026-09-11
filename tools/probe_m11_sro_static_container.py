#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

SRO=b'img/data/sro.bin\x00'
DEFAULT=b'img/data/default_sro.bin\x00'
COLOR=0x002C9A98

def hits(d,n):
    out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:return out
        out.append(p);p+=1

def hexdump(d,lo,hi,width=16):
    rows=[]
    lo=max(0,lo);hi=min(len(d),hi)
    for p in range(lo,hi,width):
        b=d[p:min(hi,p+width)]
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in b)
        rows.append(f'{p:08X}  {b.hex(" "):<47}  {asc}')
    return rows

def ascii_strings(d,minlen=5):
    for m in re.finditer(rb'[\x20-\x7e]{%d,}\x00'%minlen,d):
        yield m.start(),m.group()[:-1].decode('ascii','replace')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    sh=hits(d,SRO);dh=hits(d,DEFAULT)
    L=['# M11-P SRO static-container framing probe','',f'- SHA: `{h}`',f'- sro hits: `{[hex(x) for x in sh]}`',f'- default_sro hits: `{[hex(x) for x in dh]}`',f'- COLOR132: `0x{COLOR:08X}`','']
    for p in sh+dh:
        L += [f'## Context around filename @ `0x{p:08X}`','```text']+hexdump(d,p-0x80,p+0x180)+['```','']
        # words before/after, with size-like values highlighted
        L += ['word view:']
        for q in range((p-0x40)&~3,(p+0x100)&~3,4):
            if q<0 or q+4>len(d):continue
            u=struct.unpack_from('<I',d,q)[0]
            note=''
            if u in (132,136,0x84,0x88):note=' **SIZE-CANDIDATE**'
            L += [f'- `0x{q:08X}`: `0x{u:08X}` ({u}){note}']
        L += ['']
    # Exact tail following the 33-word structure.
    L += ['## COLOR132 tail / next-name boundary','']
    end=COLOR+132
    L += [f'- COLOR132 end: `0x{end:08X}`',f'- bytes +0x00..+0x20 after end: `{d[end:end+0x20].hex(" ")}`','```text']+hexdump(d,COLOR-0x20,COLOR+0xB0)+['```','']
    # Local img/data strings over broad region.
    local=[(p,s) for p,s in ascii_strings(d[0x2C0000:0x2D0000]) for p,s in [(p+0x2C0000,s)] if s.startswith('img/data/')]
    L += ['## img/data strings in 0x2C0000..0x2D0000','']
    for p,s in local:L += [f'- `0x{p:08X}` `{s}`']
    # Search nearby for 132/136 little endian integers.
    L += ['','## Size-word candidates ±0x400 around COLOR132','']
    for val in (132,136):
        n=struct.pack('<I',val);out=[];p=max(0,COLOR-0x400)
        stop=min(len(d),COLOR+0x400)
        while True:
            p=d.find(n,p,stop)
            if p<0:break
            out.append(p);p+=1
        L += [f'- {val}: `{[hex(x) for x in out]}`']
    # Firmware strings that may identify SRO matrix/color semantics.
    allstr=list(ascii_strings(d,6))
    sro_strings=[(p,s) for p,s in allstr if 'sro' in s.lower()]
    colour_terms=('color','colour','matrix','ccm','white','balance','wb','cct','illumin','xyz','calib','neutral','temperature')
    colorish=[(p,s) for p,s in sro_strings if any(k in s.lower() for k in colour_terms)]
    L += ['','## SRO strings with colour/calibration-related terms','']
    if colorish:
        for p,s in colorish:L += [f'- `0x{p:08X}` `{s}`']
    else:L += ['- none']
    L += ['','## All SRO strings (deduplicated text)','']
    seen=set()
    for p,s in sro_strings:
        if s in seen:continue
        seen.add(s);L += [f'- first `0x{p:08X}` `{s}`']
    L += ['','## Interpretation boundary','',
          'A nearby size-like integer or alignment gap is not accepted as file length without a repeated container framing pattern or loader/index consumer. The purpose is to distinguish an embedded file container from compiled path/default-data adjacency and to surface Leica-provided semantic names for SRO colour fields if they exist.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
