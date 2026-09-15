#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_OP_REG
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
FRAME_GLOBAL=0x43433774
AAA_LO=0x016CDE50;AAA_HI=0x016CF988
STORE_SITES=[0x01794780,0x01795ADC]
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
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
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 L=['# M11 current-frame pointer alias closure','',f'- SHA256 `{h}`','']
 # 1) Trace r2 backwards at the only direct pointer installs.
 for site in STORE_SITES:
  f=fs(d,site);lo=max(f,site-0x180);hi=site+0x30
  L += [f'## Pointer install `0x{site:08X}` function `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # 2) Find how AAA local [fp-0x24] is assigned and later used as source of +0xFC frame.
 L += ['## AAA local-state provenance for [fp,#-0x24]','']
 for i in md.disasm(d[AAA_LO:AAA_HI],AAA_LO):
  if i.id==0:continue
  if '#-0x24' in i.op_str:
   lo=max(AAA_LO,i.address-0x50);hi=min(AAA_HI,i.address+0x58)
   L += [f'### use `0x{i.address:08X}`','```asm']+[fmt(x) for x in md.disasm(d[lo:hi],lo)]+['```','']
 # 3) Search for pointer copies into any struct+0xFC, especially sourced from FRAME_GLOBAL or same producer calls.
 L += ['## Stores to structure offset +0xFC','']
 hits=[]
 for i in md.disasm(d[START:END],START):
  if i.id==0 or not i.mnemonic.startswith('str'):continue
  mems=[o for o in i.operands if o.type==ARM_OP_MEM]
  if not mems:continue
  if (mems[-1].mem.disp & 0xffffffff)!=0xfc:continue
  hits.append(i.address)
 for a0 in hits:
  f=fs(d,a0);lo=max(f,a0-0x48);hi=a0+0x28
  seq=[fmt(x) for x in md.disasm(d[lo:hi],lo)]
  L += [f'### +0xFC store `0x{a0:08X}` func `0x{f:08X}`','```asm']+seq+['```','']
 # 4) References to FRAME_GLOBAL near a +0xFC store, or direct source-setting contexts.
 L += [f'## References to current-frame global `0x{FRAME_GLOBAL:08X}` near alias writes','']
 rr=refs(d,FRAME_GLOBAL)
 for p,q,r in rr:
  lo=max(START,p-0x30);hi=min(END,q+0x50)
  text=' | '.join(fmt(x) for x in md.disasm(d[lo:hi],lo))
  if '#0xfc' in text or p in range(0x01794600,0x01794800) or p in range(0x01795980,0x01795b40):
   L.append(f'- ref `0x{p:08X}` func `0x{fs(d,p):08X}`: `{text}`')
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
