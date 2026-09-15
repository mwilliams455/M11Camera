#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct,re
from pathlib import Path
from collections import defaultdict
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000;END=0x02000000
OFFS={0x1ac:'wb0',0x1ae:'wb1',0x1b0:'wb2'}
ADDRS=[0x43430188,0x43326D7F,0x43326D80]
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fs(d,a,win=0x10000):
 for p in range(a&~3,max(START,(a&~3)-win),-4):
  if push(u32(d,p)):return p
 return a&~3
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def decmov(w,top):
 tag=w&0x0ff00000;want=0x03400000 if top else 0x03000000
 if tag!=want:return None
 return (w>>12)&15,(((w>>4)&0xf000)|(w&0xfff))
def refs(d,target):
 out=[]
 for p in range(START,END-4,4):
  m=decmov(u32(d,p),False)
  if not m:continue
  rd,lo=m
  for q in range(p+4,min(p+44,END-3),4):
   t=decmov(u32(d,q),True)
   if t and t[0]==rd:
    if ((t[1]<<16)|lo)==target:out.append((p,q,rd))
    break
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 L=['# M11 ColorSpec root +0x08 three-vector provenance','',f'- SHA256 `{h}`','']
 L += ['## Exact preparation scalar','']
 for addr in [0x016EC0C0,0x016EC4D8]:
  raw=d[addr:addr+8];L.append(f'- `{addr:#010x}` raw `{raw.hex()}` double `{struct.unpack("<d",raw)[0]!r}`')
 L += ['','## References to frame WB-field displacements','']
 hits=defaultdict(list)
 for i in md.disasm(d[START:END],START):
  if i.mnemonic=='.byte':continue
  try: ds=[o.mem.disp for o in i.operands if o.type==ARM_OP_MEM]
  except Exception: continue
  for off in OFFS:
   if off in ds:hits[off].append(i.address)
 for off,name in OFFS.items():
  L += [f'### +0x{off:X} ({name}) — {len(hits[off])} hits']
  for ha in hits[off][:100]:
   f=fs(d,ha);L += [f'#### hit `{ha:#010x}` func `{f:#010x}`','```asm']
   L += [fmt(x) for x in md.disasm(d[max(f,ha-0x50):ha+0x60],max(f,ha-0x50))]+['```']
 L += ['','## Fixed-state/global references','']
 for addr in ADDRS:
  rr=refs(d,addr);L.append(f'- `{addr:#010x}` refs `{[(hex(p),hex(q),r) for p,q,r in rr]}`')
  for p,q,r in rr[:40]:
   f=fs(d,p);L += [f'### `{addr:#010x}` ref `{p:#010x}` func `{f:#010x}`','```asm']+[fmt(x) for x in md.disasm(d[max(f,p-0x30):q+0x50],max(f,p-0x30))]+['```']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
