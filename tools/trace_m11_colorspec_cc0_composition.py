#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA=0x3FAA87D0
MATS={
 'PCS_TO_INTERNAL':0x422247D0,
 'ADAPT_BASIS':0x42224598,
 'ADAPT_BASIS_INV':0x422245E0,
}
TARGETS=[0x016ED060,0x016ECBEC,0x016EC568,0x016ED544,0x016EE62C,0x016EE5B4,0x016EEE74,0x016EF35C,0x016EF104,0x016ED670,0x016EDA24,0x016ED8E0,0x016ED644,0x016ED728,0x016F19FC,0x016F18D4,0x016F1888]
MAIN_LO=0x016F2380;MAIN_HI=0x016F2720
START=0x016E0000;END=0x01700000
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fs(d,a,win=0x12000):
 for p in range(a&~3,max(START,(a&~3)-win),-4):
  if push(u32(d,p)):return p
 return a&~3
def nxt(d,a,lim=0x3000):
 p=(a+4)&~3
 while p<min(END,a+lim):
  if push(u32(d,p)):return p
  p+=4
 return min(END,a+lim)
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def mat(d,rt):
 off=(rt-DELTA)&0xffffffff
 if 0<=off<=len(d)-72:return off,list(struct.unpack_from('<9d',d,off))
 return off,[]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 L=['# M11 ColorSpec dynamic CC0 composition trace','',f'- SHA256 `{h}`','',
    '- Goal: label exact floating 3x3 operands that produce the matrix quantized at `0x016F2710`, and close MapWhiteMatrix direction.','']
 L += ['## Fixed matrices','']
 for name,rt in MATS.items():
  off,vals=mat(d,rt)
  L += [f'### {name}',f'- runtime `0x{rt:08X}` -> file `0x{off:08X}`',f'- row-major doubles `{vals}`','']
 L += ['## Main dataflow window','```asm']+[fmt(i) for i in md.disasm(d[MAIN_LO:MAIN_HI],MAIN_LO)]+['```','']
 # Exact SetWhite/MapWhite orchestration window, including destination +0x28 producer.
 L += ['## ColorSpec SetWhite orchestration `0x016ECBEC..0x016ED060`','```asm']+[fmt(i) for i in md.disasm(d[0x016ECBEC:0x016ED060],0x016ECBEC)]+['```','']
 # MapWhiteMatrix complete body.
 L += ['## MapWhiteMatrix candidate `0x016EC568` complete body','```asm']+[fmt(i) for i in md.disasm(d[0x016EC568:0x016ECB80],0x016EC568)]+['```','']
 # xy/white-vector helper and constant point constructors.
 for lo,hi,name in [
   (0x016F19FC,0x016F1B10,'white xy -> normalized XYZ helper'),
   (0x016F18D4,0x016F19FC,'white-point constant / constructor helpers'),
   (0x016F1888,0x016F18D4,'adjacent reference-white helper')]:
  L += [f'## {name} `0x{lo:08X}..0x{hi:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 seen=set()
 for t in TARGETS:
  f=fs(d,t);e=nxt(d,f,0x2800);key=(f,e)
  if key in seen or f in (0x016EC568,0x016ECBEC):continue
  seen.add(key)
  L += [f'## Helper target `0x{t:08X}` function `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[f:e],f)]+['```','']
 L += ['## Calibration object raw-reference note','',
       '- Main reads calibration pointer from `root+0x24`.',
       '- Main directly reads doubles at calibration `+0x38` and `+0x68`, and copies 0x48-byte matrices from `+0x98` and `+0xE0`.',
       '- Known materialization later copies calibration `+0x40` and `+0x70` as CM1/CM2 records.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
