#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
FRAME_GLOBAL=0x43433774
AAA_START=0x016CDE50;AAA_END=0x016CF988
AAA_CM_CALL=0x016CEFE4
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
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 ins=list(md.disasm(d[AAA_START:AAA_END],AAA_START));idx={i.address:n for n,i in enumerate(ins)}
 L=['# M11 AAA queued frame destination trace','',f'- SHA256 `{h}`','',
    '- Goal: resolve the queued message/object chain that yields the CM destination pointer `[state+0xFC]`, then compare it with the still controller current-frame object.','']
 L += ['## Confirmed AAA -> CM handoff','```asm']+[fmt(i) for i in md.disasm(d[0x016CEFC8:0x016CEFF0],0x016CEFC8)]+['```','']
 # Every local message pointer assignment/use.
 needles=['[fp, #-0x30]','[fp, #-0x38]','[fp, #-0x24]']
 for needle in needles:
  L += [f'## AAA uses of `{needle}`','']
  seen=set()
  for i in ins:
   if needle not in i.op_str:continue
   n=idx[i.address];lo=max(0,n-14);hi=min(len(ins),n+18)
   key=(ins[lo].address,ins[hi-1].address)
   if key in seen:continue
   seen.add(key)
   L += [f'### site `0x{i.address:08X}`','```asm']+[fmt(x) for x in ins[lo:hi]]+['```','']
 # Calls in AAA around message acquisition, with targets.
 L += ['## AAA direct BL targets near message-local writes','']
 for i in ins:
  t=blt(i.address,u32(d,i.address))
  if t is None:continue
  n=idx[i.address]
  text=' | '.join(fmt(x) for x in ins[max(0,n-5):min(len(ins),n+7)])
  if any(k in text for k in ('#-0x30','#-0x38','#-0x24','#0x1c','#0xfc')):
   L.append(f'- call `0x{i.address:08X}` -> `0x{t:08X}`: `{text}`')
 # The exact nested object chain before CM.
 L += ['','## Nested object chain immediately preceding CM','```asm']+[fmt(i) for i in md.disasm(d[0x016CE680:0x016CE730],0x016CE680)]+['```','']
 # Scan FRAME_GLOBAL loads followed by a store to +0xFC in same short basic window.
 L += [f'## FRAME_GLOBAL `0x{FRAME_GLOBAL:08X}` load -> struct+0xFC candidates','']
 rr=refs(d,FRAME_GLOBAL);cand=0
 for p,q,r in rr:
  lo=p;hi=min(END,q+0x100);seq=list(md.disasm(d[lo:hi],lo));text=' | '.join(fmt(x) for x in seq)
  if '#0xfc]' in text or '#0xfc' in text:
   cand+=1;L += [f'### candidate ref `0x{p:08X}` func `0x{fs(d,p):08X}`','```asm']+[fmt(x) for x in seq]+['```','']
 L += [f'- candidate count `{cand}`','']
 # Current frame producer snippets.
 for site in STORE_SITES:
  L += [f'## Current-frame producer `0x{site:08X}`','```asm']+[fmt(i) for i in md.disasm(d[site-0x60:site+0x70],site-0x60)]+['```','']
 # Disassemble the fallback frame-base allocator/accessor called immediately before +0x240.
 L += ['## Fallback frame-base provider 0x019C80BC','```asm']+[fmt(i) for i in md.disasm(d[0x019C80BC:0x019C81BC],0x019C80BC)]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
