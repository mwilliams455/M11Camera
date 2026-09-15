#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA=0x3FAA87D0
RUNTIME=0x42224B38
COUNT=31
STRIDE=32

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    off=RUNTIME-DELTA
    rows=[]
    for i in range(COUNT):
        vals=struct.unpack_from('<4d',d,off+i*STRIDE)
        rows.append(vals)
    L=['# M11 ColorSpec isotemperature table','',f'- SHA256 `{h}`',f'- runtime `{RUNTIME:#010x}`',f'- file offset `{off:#010x}`',f'- entries `{COUNT}`',f'- stride `{STRIDE}` bytes','','```text']
    for i,row in enumerate(rows):
        L.append(f'{i:02d}: '+', '.join(f'{v:.17g}' for v in row))
    L += ['```','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
