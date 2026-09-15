#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
R2Y=0x0176E75C
CM=0x016EB010
R2Y_CALLS=[0x0176D948,0x0176DD94,0x017B878C,0x017B8C88,0x017B9118,0x017B95E0,0x017B99CC,0x017BA0D4,0x017BA52C,0x017BA99C,0x017BAE0C,0x017BB27C]
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b):s=1<<(b-1);return (v^s)-s
def blt(a,w):
 if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
 return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fs(d,a,window=0x40000):
 for p in range(a&~3,max(START,(a&~3)-window),-4):
  if push(u32(d,p)):return p
 return a&~3
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 # direct callers map for selected functions and caller funcs
 funcs=set([R2Y,CM])
 for c in R2Y_CALLS:funcs.add(fs(d,c))
 callers={t:[] for t in funcs}
 for p in range(START,END,4):
  t=blt(p,u32(d,p))
  if t in callers:callers[t].append(p)
 L=['# M11 CM frame pointer -> R2Y arg3 identity trace','',f'- SHA256 `{h}`','']
 # CM AAA handoff
 L += ['## AAA -> CM pointer handoff','```asm']+[fmt(i) for i in md.disasm(d[0x016CEFC8:0x016CEFF0],0x016CEFC8)]+['```','']
 # R2Y caller functions: show function prologue, all str r{0..3} to fp negative slots early, and call window
 for c in R2Y_CALLS:
  f=fs(d,c); L += [f'## R2Y call `0x{c:08X}` containing function `0x{f:08X}`',f'- direct callers of containing function: `{[hex(x) for x in callers.get(f,[])]}`','### prologue / early argument saves','```asm']
  L += [fmt(i) for i in md.disasm(d[f:min(c,f+0x120)],f)]+['```','### call window','```asm']
  L += [fmt(i) for i in md.disasm(d[max(f,c-0x80):c+0x20],max(f,c-0x80))]+['```','']
 # One level of parent caller contexts for 17B-family funcs
 seen=set()
 for c in R2Y_CALLS:
  f=fs(d,c)
  for pc in callers.get(f,[]):
   if pc in seen:continue
   seen.add(pc);pf=fs(d,pc)
   L += [f'## Parent call `0x{pc:08X}` -> wrapper `0x{f:08X}` parent func `0x{pf:08X}`','```asm']
   L += [fmt(i) for i in md.disasm(d[max(pf,pc-0x90):pc+0x28],max(pf,pc-0x90))]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
