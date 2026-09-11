#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

TAGS=(b'DPCS',b'DPCE',b'R2YS',b'R2YE',b'ELFS',b'ELFE',b'B2BS',b'B2BE',b'SROS',b'SROE')

def hits(d,n):
    out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:return out
        out.append(p);p+=1

def ascii_at(d,p,n=100):
    if not 0<=p<len(d):return None
    e=d.find(b'\0',p,min(len(d),p+n))
    if e<0 or e-p<4:return None
    try:s=d[p:e].decode('ascii')
    except:return None
    return s if all(32<=ord(c)<127 for c in s) else None

def context(d,p,r=0x40):
    lo=max(0,p-r);hi=min(len(d),p+r)
    out=[]
    for q in range(lo,hi,16):
        b=d[q:min(hi,q+16)];asc=''.join(chr(x) if 32<=x<127 else '.' for x in b)
        out.append(f'{q:08X}  {b.hex(" "):<47}  {asc}')
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    L=['# M11-P resource link/tag probe','',f'- SHA: `{h}`','']
    for tag in TAGS:
        hs=hits(d,tag)
        L += [f'## `{tag.decode()}` hits: `{[hex(x) for x in hs]}`','']
        for p in hs[:100]:
            v=struct.unpack_from('<I',d,p+4)[0] if p+8<=len(d) else None
            targets=[]
            if v is not None:
                for base_name,base in (('tag',p),('value_word',p+4),('after_pair',p+8)):
                    t=base+v
                    s=ascii_at(d,t)
                    s4=d[t:t+4] if 0<=t<len(d)-4 else b''
                    targets.append((base_name,t,s,s4))
            L += [f'### `{tag.decode()}` @ `0x{p:08X}`',f'- following u32: `{None if v is None else hex(v)}` ({v})']
            for base,t,s,s4 in targets:
                L += [f'- {base}+value -> `0x{t:08X}` first4=`{s4.hex()}` ascii=`{s}`']
            L += ['```text']+context(d,p)+['```','']
    # Explicit path/link relationships around known region.
    names=(b'img/data/sro.bin\x00',b'img/data/R2Y_CC0_CM.bin\x00',b'img/data/r2y.bin\x00')
    L += ['## Path occurrences and nearest tag within ±0x40','']
    taghits=[(p,t.decode()) for t in TAGS for p in hits(d,t)]
    for n in names:
        for p in hits(d,n):
            near=sorted((abs(tp-p),tp,t) for tp,t in taghits if abs(tp-p)<=0x40)
            L += [f'- `{n[:-1].decode()}` @ `0x{p:08X}` nearby tags `{[(hex(tp),t,hex(dist)) for dist,tp,t in near]}`']
    L += ['','## Interpretation boundary','',
          'A tag+relative-offset rule is accepted only when the arithmetic lands exactly on another known tag/path/object and repeats across independent families. This probe does not by itself assign ownership of COLOR132; it establishes the static resource-container grammar needed for that assignment.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
