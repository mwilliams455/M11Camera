#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TARGETS=[0x016EE13C,0x016EDFE4,0x016F1844,0x01C4BAC0]
START=0x01000000;END=0x02000000
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def nxt(d,a,lim=0x3000):
 p=(a+4)&~3
 while p<min(END,a+lim):
  if push(u32(d,p)):return p
  p+=4
 return min(END,a+lim)
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 L=['# M11 CC0 quantizer helper semantics','',f'- SHA256 `{h}`','']
 for t in TARGETS:
  e=nxt(d,t,0x3000)
  L += [f'## `0x{t:08X}` to next A32 push `0x{e:08X}`','```asm']+[fmt(i) for i in md.disasm(d[t:e],t)]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
