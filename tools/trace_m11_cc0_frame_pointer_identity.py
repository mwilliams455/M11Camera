#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
FRAME_GLOBAL=0x43433774
AAA_STATE_GLOBAL=0x43379928
AAA_CTOR=0x0178A3A0
AAA_START=0x016CDE50
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
def next_push(d,a,limit=0x3000):
 p=(a+4)&~3
 while p<min(END,a+limit):
  if push(u32(d,p)):return p
  p+=4
 return min(END,a+limit)
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
 return [p for p in range(lo,hi,4) if blt(p,u32(d,p))==target]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 L=['# M11 AAA state constructor -> current frame closure','',f'- SHA256 `{h}`','',
    f'- Candidate AAA state object: `0x{AAA_STATE_GLOBAL:08X}`; constructor `0x{AAA_CTOR:08X}` writes callbacks at +0x100/+0x104 and a pointer at +0xFC.','']
 # Full constructor to identify argument mapping and event behaviour.
 ce=next_push(d,AAA_CTOR,0x1000)
 L += [f'## Candidate AAA state constructor `0x{AAA_CTOR:08X}` -> next push `0x{ce:08X}`','```asm']+[fmt(i) for i in md.disasm(d[AAA_CTOR:ce],AAA_CTOR)]+['```','']
 # Direct callers and register setup, especially r1 which is expected to feed state+0xFC.
 cs=callers(d,AAA_CTOR)
 L += [f'## Direct callers of constructor',f'- callers `{[hex(x) for x in cs]}`','']
 for ca in cs:
  pf=fs(d,ca);lo=max(pf,ca-0xc0);hi=min(END,ca+0x28)
  L += [f'### call `0x{ca:08X}` parent `0x{pf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # Absolute references to candidate state object; look for queue/event packaging and state+0xFC consumers.
 rr=refs(d,AAA_STATE_GLOBAL)
 L += [f'## References to candidate state object `0x{AAA_STATE_GLOBAL:08X}`',f'- ref count `{len(rr)}`','']
 for p,q,r in rr:
  f=fs(d,p);lo=max(f,p-0x60);hi=min(END,q+0x90)
  L += [f'### ref `0x{p:08X}` func `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # Side-by-side AAA consumer chain.
 L += ['## AAA queued consumer -> CM','```asm']+[fmt(i) for i in md.disasm(d[0x016CE0A4:0x016CE0E4],0x016CE0A4)]+[fmt(i) for i in md.disasm(d[0x016CE6C4:0x016CE714],0x016CE6C4)]+[fmt(i) for i in md.disasm(d[0x016CEFD8:0x016CEFE8],0x016CEFD8)]+['```','']
 # Current frame producers and all constructor calls in their containing still controller.
 sf=fs(d,STORE_SITES[0]);se=next_push(d,sf,0x10000)
 L += [f'## Still controller `0x{sf:08X}` constructor-call search','']
 internal=[p for p in range(sf,se,4) if blt(p,u32(d,p))==AAA_CTOR]
 L += [f'- calls to AAA constructor inside still controller: `{[hex(x) for x in internal]}`','']
 for ca in internal:
  L += [f'### still-controller call `0x{ca:08X}`','```asm']+[fmt(i) for i in md.disasm(d[max(sf,ca-0xa0):ca+0x20],max(sf,ca-0xa0))]+['```','']
 for site in STORE_SITES:
  L += [f'## Current-frame install `0x{site:08X}`','```asm']+[fmt(i) for i in md.disasm(d[site-0x40:site+0x28],site-0x40)]+['```','']
 # Any function that references both the state global and FRAME_GLOBAL is highly probative.
 fr=refs(d,FRAME_GLOBAL)
 fs_state={fs(d,p) for p,_,_ in rr};fs_frame={fs(d,p) for p,_,_ in fr};both=sorted(fs_state&fs_frame)
 L += ['## Functions referencing both AAA state global and current-frame global',f'- functions `{[hex(x) for x in both]}`','']
 for f in both:
  e=next_push(d,f,0x5000)
  L += [f'### shared function `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[f:min(e,f+0x900)],f)]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
