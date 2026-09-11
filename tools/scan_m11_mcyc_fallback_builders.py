#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
# GCC A32 commonly emits MOV #positive and MVN #(abs(negative)-1).
MARKERS={('mov',77):77,('mov',150):150,('mov',29):29,('mov',128):128,('mvn',42):-43,('mvn',84):-85,('mvn',106):-107,('mvn',20):-21}
def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def ror32(x,n):n&=31;return ((x>>n)|((x<<(32-n))&0xffffffff))&0xffffffff if n else x&0xffffffff
def dpimm(w):
 if ((w>>25)&7)!=1:return None
 op=(w>>21)&0xf
 if op not in (13,15):return None
 v=ror32(w&0xff,2*((w>>8)&0xf));return ('mov' if op==13 else 'mvn',v)
def pro(d,p,back=0x6000):
 for x in range(p&~3,max(0,(p&~3)-back)-1,-4):
  w=u32(d,x)
  if (w&0xffff0000)==0xe92d0000 and (w&(1<<14)):return x
 return max(0,p-0x1000)
def end(d,s,cap=0x7000):
 for p in range(s+4,min(len(d)-4,s+cap),4):
  w=u32(d,p)
  if w==0xe12fff1e or ((w&0xffff0000)==0xe8bd0000 and (w&(1<<15))):return p+4
 return min(len(d),s+cap)
def md():c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);c.skipdata=True;return c
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise ValueError(h)
 by=defaultdict(list)
 for p in range(0x01000000,min(0x02000000,len(d)-4),4):
  z=dpimm(u32(d,p))
  if z in MARKERS:by[pro(d,p)].append((p,z[0],z[1],MARKERS[z]))
 ranked=[]
 for s,hs in by.items():
  keys=set((k,v) for _,k,v,_ in hs); score=len(keys&set(MARKERS));
  if score>=6:ranked.append((score,s,hs))
 ranked.sort(reverse=True)
 L=['# M11-P MCYC/YCC fallback builder fingerprint','',f'- SHA: `{h}`',f'- marker set: `{[(k,v,s) for (k,v),s in MARKERS.items()]}`',f'- candidates score>=6/8: `{len(ranked)}`','']
 for score,s,hs in ranked:
  e=end(d,s);L += [f'## `0x{s:08X}..0x{e:08X}`',f'- score: `{score}/8`',f'- marker sites: `{[(hex(p),k,v,sv) for p,k,v,sv in hs]}`','', '```asm']
  lo=max(s,min(p for p,_,_,_ in hs)-0x100);hi=min(e,max(p for p,_,_,_ in hs)+0x180)
  for i in md().disasm(d[lo:hi],lo):L.append(f'0x{i.address:08X}: {i.mnemonic} {i.op_str}')
  L += ['```','']
 L += ['## Boundary','','A second candidate is useful only if the constants are stored into a coherent MCYC prefix and the function then continues into CtrlMultiAxis boundary/area/MCK/MCL construction. The known Category-24 YC wrapper is expected as a positive control.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
