#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000;END=0x01C00000
R2Y=0x0176E75C;CM=0x016EB010;FRAME_GLOBAL=0x43433774
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
 funcs=set([R2Y,CM])
 for c in R2Y_CALLS:funcs.add(fs(d,c))
 callers={t:[] for t in funcs}
 for p in range(START,END,4):
  t=blt(p,u32(d,p))
  if t in callers:callers[t].append(p)
 L=['# M11 CM frame pointer -> R2Y arg3 identity trace','',f'- SHA256 `{h}`','']
 aaaf=fs(d,0x016CEFE4)
 L += [f'## AAA dispatcher function start `0x{aaaf:08X}`','```asm']+[fmt(i) for i in md.disasm(d[aaaf:min(aaaf+0x180,0x016CED80)],aaaf)]+['```','## AAA -> CM pointer handoff','```asm']+[fmt(i) for i in md.disasm(d[0x016CEFC8:0x016CEFF0],0x016CEFC8)]+['```','']
 rr=refs(d,FRAME_GLOBAL)
 L += [f'## Global `0x{FRAME_GLOBAL:08X}` references',f'- total refs `{len(rr)}`','']
 # Classify every reference by the next few instructions so writes are visible without dumping the giant controller.
 for p,q,r in rr:
  seq=list(md.disasm(d[p:min(END,q+0x24)],p))
  text=' | '.join(fmt(i) for i in seq)
  iswrite=any(i.mnemonic.startswith('str') and f'[r{r}' in i.op_str for i in seq)
  isload=any(i.mnemonic.startswith('ldr') and f'[r{r}' in i.op_str for i in seq)
  if iswrite:
   L.append(f'- WRITE ref `0x{p:08X}` func `0x{fs(d,p):08X}`: `{text}`')
 L += ['','### Representative load contexts','']
 for p,q,r in rr[:40]:
  seq=list(md.disasm(d[p:min(END,q+0x18)],p));text=' | '.join(fmt(i) for i in seq)
  if any(i.mnemonic.startswith('ldr') and f'[r{r}' in i.op_str for i in seq):L.append(f'- LOAD ref `0x{p:08X}`: `{text}`')
 # R2Y call parent chain retained only for the still wrappers that pass FRAME_GLOBAL as r1.
 for c in R2Y_CALLS:
  f=fs(d,c)
  L += ['',f'## R2Y call `0x{c:08X}` wrapper `0x{f:08X}`','### prologue','```asm']+[fmt(i) for i in md.disasm(d[f:min(c,f+0x40)],f)]+['```','### call window','```asm']+[fmt(i) for i in md.disasm(d[max(f,c-0x40):c+0x18],max(f,c-0x40))]+['```']
 seen=set()
 for c in R2Y_CALLS:
  f=fs(d,c)
  for pc in callers.get(f,[]):
   if pc in seen:continue
   seen.add(pc);pf=fs(d,pc)
   L += ['',f'## Parent `0x{pc:08X}` -> wrapper `0x{f:08X}`','```asm']+[fmt(i) for i in md.disasm(d[max(pf,pc-0x50):pc+0x18],max(pf,pc-0x50))]+['```']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
