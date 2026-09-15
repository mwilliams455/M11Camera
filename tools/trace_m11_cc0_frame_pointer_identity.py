#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
FRAME_GLOBAL=0x43433774
AAA_CM_CALL=0x016CEFE4
CM_START=0x016EB010
STORE_SITES=[0x01794780,0x01795ADC]
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
def decmov(w,kind):
 tag=w&0x0ff00000;want=0x03000000 if kind=='w' else 0x03400000
 if tag!=want:return None
 return (w>>12)&15,(((w>>4)&0xf000)|(w&0xfff))
def refs(d,target):
 out=[]
 for p in range(START,END-4,4):
  m=decmov(u32(d,p),'w')
  if not m:continue
  rd,lo=m
  for q in range(p+4,min(p+40,END-3),4):
   t=decmov(u32(d,q),'t')
   if t and t[0]==rd:
    if ((t[1]<<16)|lo)==target:out.append((p,q,rd))
    break
 return out
def callers(d,target,lo=START,hi=END):
 out=[]
 for p in range(lo,hi,4):
  if blt(p,u32(d,p))==target:out.append(p)
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 aaaf=fs(d,AAA_CM_CALL)
 L=['# M11 CM destination frame -> R2Y frame closure','',f'- SHA256 `{h}`',f'- AAA/CM dispatcher function `0x{aaaf:08X}` contains call `0x{AAA_CM_CALL:08X}` -> CM start `0x{CM_START:08X}`.','']
 # CM destination handoff itself.
 L += ['## AAA -> CM destination pointer','```asm']+[fmt(i) for i in md.disasm(d[0x016CEFC8:0x016CEFF0],0x016CEFC8)]+['```','']
 # AAA function start and its direct callers.
 L += [f'## AAA dispatcher start `0x{aaaf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[aaaf:min(END,aaaf+0x100)],aaaf)]+['```','']
 ac=callers(d,aaaf)
 L += [f'## Direct callers of AAA dispatcher `0x{aaaf:08X}`',f'- callers `{[hex(x) for x in ac]}`','']
 for ca in ac:
  pf=fs(d,ca);lo=max(pf,ca-0xc0);hi=min(END,ca+0x30)
  L += [f'### caller `0x{ca:08X}` parent `0x{pf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # One more level: direct callers of parents, useful when AAA is reached through event dispatch wrappers.
 parents=sorted(set(fs(d,x) for x in ac))
 for pf in parents:
  pcs=callers(d,pf)
  L += [f'## Parents calling AAA-parent `0x{pf:08X}`',f'- callers `{[hex(x) for x in pcs]}`','']
  for ca in pcs[:32]:
   ppf=fs(d,ca);lo=max(ppf,ca-0x80);hi=min(END,ca+0x24)
   L += [f'### grandparent call `0x{ca:08X}` parent `0x{ppf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # Current-frame pointer installs retained for side-by-side comparison.
 for site in STORE_SITES:
  f=fs(d,site);lo=max(f,site-0x90);hi=site+0x28
  L += [f'## Current-frame install `0x{site:08X}` function `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # Any absolute FRAME_GLOBAL references inside AAA caller ancestry are especially probative.
 L += [f'## FRAME_GLOBAL `0x{FRAME_GLOBAL:08X}` references inside AAA ancestry','']
 rr=refs(d,FRAME_GLOBAL)
 ancestry=[]
 spans=[]
 for f in [aaaf]+parents:
  spans.append((f,min(END,f+0x6000)))
 for ca in ac:
  pf=fs(d,ca);spans.append((pf,min(END,pf+0x6000)))
 for p,q,r in rr:
  if any(lo<=p<hi for lo,hi in spans):
   lo=max(START,p-0x50);hi=min(END,q+0x60)
   ancestry.append(p)
   L += [f'### FRAME_GLOBAL ref `0x{p:08X}` func `0x{fs(d,p):08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 L += [f'- ancestry FRAME_GLOBAL refs count `{len(ancestry)}`','']
 # Search for calls to AAA dispatcher from the still controller neighbourhood too.
 still_calls=[x for x in ac if 0x01780000<=x<0x017C0000]
 L += ['## Closure summary inputs',f'- AAA direct calls from still-controller address band 0x0178xxxx-0x017Bxxxx: `{[hex(x) for x in still_calls]}`',f'- Current-frame installs remain `{[hex(x) for x in STORE_SITES]}`.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
