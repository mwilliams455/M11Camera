#!/usr/bin/env python3
"""Probe exact M11-P 2.6.1 for R2Y debug/symbol metadata remnants.

The matching Milbeaut build uses GCC with -g3 -gdwarf-2. If Leica retained
symbol/DWARF names or source-file references, they may bridge the known R2Y
strings/data sections directly to ARM text addresses. This tool emits only
string offsets/counts and bounded derived metadata, never firmware bytes.
"""
from __future__ import annotations
import argparse, hashlib, re
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
NEEDLES=[
 b'imr2yset.c', b'imr2yctrl2.c', b'imr2yctrl.c', b'imr2yutility3.c',
 b'Im_R2Y_Set_Gamma_Table', b'Im_R2Y_Ctrl_Gamma',
 b'img_macro_drv_r2y_select_gamma_paraset',
 b'.debug_info', b'.debug_abbrev', b'.debug_str', b'.debug_line',
 b'.symtab', b'.strtab', b'.ARM.attributes', b'aeabi',
 b'GCC: (GNU)', b'GNU C', b'DWARF',
]
PRINTABLE=re.compile(rb'[\x20-\x7e]{6,}')

def hits(data,n):
 out=[];p=0
 while True:
  p=data.find(n,p)
  if p<0:return out
  out.append(p);p+=1

def nearby(data,off,r=0x180):
 a=max(0,off-r);b=min(len(data),off+r);rows=[]
 for m in PRINTABLE.finditer(data[a:b]):
  p=a+m.start();txt=m.group().decode('ascii',errors='replace')
  rows.append((abs(p-off),p,txt))
 rows.sort();return rows[:18]

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected SHA {sha}')
 lines=['# M11-P R2Y debug/symbol metadata probe','',f'- exact unpacked SHA-256 `{sha}`','', '## Target hits','']
 for n in NEEDLES:
  hs=hits(data,n); label=n.decode('ascii',errors='replace')
  lines += [f'### `{label}` — `{len(hs)}` hit(s)','']
  for off in hs[:24]:
   lines.append(f'- `0x{off:08x}`')
   for _,p,t in nearby(data,off):
    safe=t.replace('`', "'")
    lines.append(f'  - `{p-off:+#x}` / `0x{p:08x}` — `{safe}`')
  if len(hs)>24:lines.append(f'- {len(hs)-24} additional hit(s) omitted')
  lines.append('')
 lines += ['## Interpretation boundary','', 'String/source/debug markers prove metadata presence only. A function text address is not established unless a symbol/DWARF record is parsed or independently corroborated.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(x.output)
if __name__=='__main__':main()
