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
AAA_CTOR_CALLER=0x017B4EC4
AAA_CTOR_CALL=0x017B5070
STORE_SITES=[0x01794780,0x01795ADC]
def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b): s=1<<(b-1); return (v^s)-s
def blt(a,w):
 if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
 return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def push(w): return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fs(d,a,window=0x40000):
 for p in range(a&~3,max(START,(a&~3)-window),-4):
  if push(u32(d,p)): return p
 return a&~3
def next_push(d,a,limit=0x5000):
 p=(a+4)&~3
 while p<min(END,a+limit):
  if push(u32(d,p)):return p
  p+=4
 return min(END,a+limit)
def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
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
def callers(d,target,lo=START,hi=END): return [p for p in range(lo,hi,4) if blt(p,u32(d,p))==target]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
 L=['# M11 frame -> AAA state+0xFC closure','',f'- SHA256 `{h}`','',
    f'- Proven: `0x{AAA_CTOR:08X}` stores its incoming r1 verbatim to `0x{AAA_STATE_GLOBAL:08X}+0xFC`.','',
    f'- Proven: sole direct caller `0x{AAA_CTOR_CALL:08X}` passes local `[fp-0x1C]` as r1. This trace resolves that local.','']
 # Full caller so local -0x1c source is visible from prologue to constructor call.
 ce=next_push(d,AAA_CTOR_CALLER,0x3000)
 L += [f'## Full constructor caller `0x{AAA_CTOR_CALLER:08X}` -> next push `0x{ce:08X}`','```asm']+[fmt(i) for i in md.disasm(d[AAA_CTOR_CALLER:ce],AAA_CTOR_CALLER)]+['```','']
 # Highlight every use of fp-0x1c in the function with context.
 seq=list(md.disasm(d[AAA_CTOR_CALLER:ce],AAA_CTOR_CALLER));idx={i.address:n for n,i in enumerate(seq)}
 L += ['## Uses / definitions of `[fp,#-0x1C]`','']
 for i in seq:
  if '#-0x1c' not in i.op_str:continue
  n=idx[i.address]
  L += [f'### site `0x{i.address:08X}`','```asm']+[fmt(x) for x in seq[max(0,n-10):min(len(seq),n+12)]]+['```','']
 # Direct callers of 17B4EC4: identify its argument source(s).
 cs=callers(d,AAA_CTOR_CALLER)
 L += [f'## Direct callers of `0x{AAA_CTOR_CALLER:08X}`',f'- callers `{[hex(x) for x in cs]}`','']
 for ca in cs:
  pf=fs(d,ca);lo=max(pf,ca-0xc0);hi=min(END,ca+0x30)
  L += [f'### caller `0x{ca:08X}` parent `0x{pf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 # Find direct references to current-frame global in caller and caller ancestry.
 rr=refs(d,FRAME_GLOBAL)
 funcs={AAA_CTOR_CALLER}|{fs(d,x) for x in cs}
 L += [f'## Current-frame global `0x{FRAME_GLOBAL:08X}` refs in caller ancestry','']
 count=0
 for p,q,r in rr:
  f=fs(d,p)
  if f not in funcs:continue
  count+=1;lo=max(f,p-0x70);hi=min(END,q+0x90)
  L += [f'### ref `0x{p:08X}` func `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[lo:hi],lo)]+['```','']
 L += [f'- matched refs `{count}`','']
 # Search calls to constructor caller inside current-frame still-controller region and dump setup.
 L += ['## Calls from still-controller address band to constructor caller','']
 still=[x for x in cs if 0x01780000<=x<0x017C0000]
 L += [f'- direct calls `{[hex(x) for x in still]}`','']
 # Compare current-frame store sites and constructor caller entry for structural proof.
 for site in STORE_SITES:
  L += [f'## Current-frame install `0x{site:08X}`','```asm']+[fmt(i) for i in md.disasm(d[site-0x60:site+0x30],site-0x60)]+['```','']
 # Absolute refs to AAA state in constructor caller parent functions may expose lifecycle dispatch.
 ar=refs(d,AAA_STATE_GLOBAL)
 parentfuncs={fs(d,x) for x in cs}
 L += [f'## AAA-state refs in parents of constructor caller','']
 for p,q,r in ar:
  f=fs(d,p)
  if f in parentfuncs:
   L += [f'### state ref `0x{p:08X}` func `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[max(f,p-0x50):min(END,q+0x80)],max(f,p-0x50))]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
