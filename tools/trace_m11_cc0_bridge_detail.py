#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
SECTIONS=[
 ('r2y_dispatch_prologue',0x0176E75C,0x0176E900),
 ('r2y_dynamic_cc0_bridge',0x017700F0,0x01770420),
 ('r2y_control_commit',0x0176FDF0,0x0176FF20),
 ('r2y_builder_entry',0x0172C19C,0x0172C780),
 ('common_r2y_setter',0x01B1CDA4,0x01B1D160),
]
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b):s=1<<(b-1);return (v^s)-s
def blt(a,w):
 if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
 return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 L=['# M11 dynamic CC0 -> R2Y bridge detail','',f'- SHA256 `{h}`','']
 for name,lo,hi in SECTIONS:
  L += [f'## {name} `0x{lo:08X}..0x{hi:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 target=0x0176E75C;callers=[]
 for p in range(0x01500000,0x01B00000,4):
  if blt(p,u32(d,p))==target:callers.append(p)
 L += ['## Direct callers of R2Y dispatch',f'- `{[hex(x) for x in callers]}`','']
 for c in callers:
  lo=max(0,c-0x60);hi=c+0x30
  L += [f'### caller context `0x{c:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
