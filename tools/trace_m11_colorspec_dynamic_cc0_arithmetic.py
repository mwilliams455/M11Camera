#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from collections import defaultdict
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_OP_IMM
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x016E0000;END=0x01700000
CORE0=0x016F2108;CORE1=0x016F27B0
HELPERS=[0x016F1FB4,0x016F1CB8,0x016F0998,0x016ED8E0,0x016EDA24,0x016ED060,0x016ECBEC,0x016ED544,0x016EE62C]
OFFS=set(range(0x28,0x54,4))
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
 if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
 return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fs(d,a,win=0x20000):
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
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 callmap=defaultdict(list)
 for p in range(START,END,4):
  t=bt(p,u32(d,p))
  if t is not None:callmap[t].append(p)
 L=['# M11 ColorSpec dynamic CC0 arithmetic trace','',f'- SHA256 `{h}`','- Focus: producer-side arithmetic for ColorSpec root `+0x28..+0x50` (9 coefficients + control/scale field).','']
 L += ['## ColorSpec live core','```asm']+[fmt(i) for i in md.disasm(d[CORE0:CORE1],CORE0)]+['```','']
 # Calls inside core and immediate caller/callee context.
 L += ['## Calls from live core','']
 core_calls=[]
 for p in range(CORE0,CORE1,4):
  t=bt(p,u32(d,p))
  if t is not None:
   core_calls.append((p,t));L.append(f'- `0x{p:08X}` -> `0x{t:08X}`')
 L += ['','## Exact CC0-field displacement accesses in CM/ColorSpec band','']
 hits=[]
 for i in md.disasm(d[START:END],START):
  if i.mnemonic=='.byte':continue
  try:
   ds=[o.mem.disp for o in i.operands if o.type==ARM_OP_MEM]
  except Exception:continue
  if any(x in OFFS for x in ds):
   hits.append(i.address)
 for ha in hits:
  f=fs(d,ha); lo=max(f,ha-0x40);hi=min(END,ha+0x70)
  L += [f'### hit `0x{ha:08X}` func `0x{f:08X}`','```asm']+[fmt(x) for x in md.disasm(d[lo:hi],lo)]+['```','']
 # Dump each known/helper and every direct core callee in a bounded function span.
 targets=sorted(set(HELPERS+[t for _,t in core_calls if START<=t<END]))
 L += ['## Helper functions','']
 for t in targets:
  f=fs(d,t);e=nxt(d,f,0x1800)
  L += [f'### target `0x{t:08X}` function `0x{f:08X}` callers `{[hex(x) for x in callmap.get(t,[])]}`','```asm']+[fmt(i) for i in md.disasm(d[f:e],f)]+['```','']
 # Constants likely to reveal float/fixed-point normalization near core/helpers.
 constants={0x3f800000:'1.0f',0x3f000000:'0.5f',0x40000000:'2.0f',0x3b800000:'1/256f',0x3a800000:'1/1024f',0x00000200:'512',0x00000400:'1024'}
 L += ['## Immediate/literal constant probes','']
 for v,name in constants.items():
  raw=struct.pack('<I',v);pos=[];p=START
  while True:
   p=d.find(raw,p,END)
   if p<0:break
   pos.append(p);p+=1
  near=[x for x in pos if CORE0-0x4000<=x<=CORE1+0x4000]
  L.append(f'- `{name}` `0x{v:08X}` nearby aligned/raw occurrences `{[hex(x) for x in near[:80]]}`')
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
