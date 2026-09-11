#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
# Closed naturally-packed CtrlMultiAxis geometry.
TARGETS={0x12:'boundary_start',0x20:'boundary_bytes',0x28:'area_bytes',0x32:'area_start',0x5a:'mck_start',0x438:'mck_bytes',0x492:'mcl_start',0x2d0:'mcl_bytes',0x762:'blend_start',0x2a:'blend_bytes',0x78c:'total_bytes'}
CORE={0x438,0x2d0,0x492,0x762,0x78c}
def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def ror32(x,n): n&=31; return ((x>>n)|((x<<(32-n))&0xffffffff))&0xffffffff if n else x&0xffffffff
def immvals(w):
 out=[]
 # MOVW immediate.
 if (w & 0x0ff00000)==0x03000000:
  out.append((((w>>4)&0xf000)|(w&0xfff),'movw'))
 # MOVT retained only diagnostically; its value is a high half, not target scalar.
 # A32 data-processing immediate: AND/EOR/SUB/RSB/ADD/.../MOV/BIC/MVN.
 if ((w>>25)&7)==1:
  opcode=(w>>21)&0xf; imm=ror32(w&0xff,2*((w>>8)&0xf))
  names=['and','eor','sub','rsb','add','adc','sbc','rsc','tst','teq','cmp','cmn','orr','mov','bic','mvn']
  out.append((imm,names[opcode]))
 return out
def prologue(d,p,back=0x6000):
 q=p&~3; lo=max(0,q-back)
 for x in range(q,lo-1,-4):
  w=u32(d,x)
  # STMDB sp!, reglist with LR; ordinary GCC push {...,lr}
  if (w & 0xffff0000)==0xe92d0000 and (w & (1<<14)):
   return x
 return max(lo,p-0x1000)
def ret_after(d,st,cap=0x9000):
 hi=min(len(d)-4,st+cap)
 for p in range(st+4,hi+1,4):
  w=u32(d,p)
  # bx lr
  if w==0xe12fff1e:return p+4
  # ldmia sp!, {...,pc} / pop {...,pc}
  if (w&0xffff0000)==0xe8bd0000 and (w&(1<<15)):return p+4
 return hi+4
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);c.skipdata=True;return c
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise ValueError(h)
 hits=[]
 # Principal executable window plus nearby driver code; avoid scanning data as code past 0x02000000.
 lo,hi=0x01000000,min(0x02000000,len(d)-4)
 for p in range(lo,hi,4):
  for v,k in immvals(u32(d,p)):
   if v in TARGETS:hits.append((p,v,k))
 by=defaultdict(list)
 for p,v,k in hits:by[prologue(d,p)].append((p,v,k))
 scored=[]
 for st,hs in by.items():
  vals=set(v for _,v,_ in hs); core=len(vals&CORE); alln=len(vals)
  # Strong candidates require >=2 core geometry values, or one core + >=4 total layout values.
  if core>=2 or (core>=1 and alln>=4): scored.append((core,alln,st,vals,hs))
 scored.sort(reverse=True)
 L=['# M11-P CtrlMultiAxis layout-builder scan','',f'- SHA: `{h}`',f'- target geometry: `{ {hex(k):v for k,v in TARGETS.items()} }`',f'- immediate hits: `{len(hits)}`',f'- ranked candidate functions: `{len(scored)}`','']
 for core,alln,st,vals,hs in scored[:40]:
  en=ret_after(d,st)
  L += [f'## `0x{st:08X}..0x{en:08X}`',f'- core layout matches: `{core}`',f'- total distinct layout matches: `{alln}`',f'- values: `{[(hex(v),TARGETS[v]) for v in sorted(vals)]}`',f'- sites: `{[(hex(p),hex(v),k) for p,v,k in hs]}`','', '```asm']
  # Bound report around matching sites rather than dumping huge routines.
  for p,v,k in hs:
   L.append(f'; --- {TARGETS[v]} / 0x{v:X} at 0x{p:08X} ({k}) ---')
   a0=max(st,p-0x60);b0=min(en,p+0x80)
   for i in md().disasm(d[a0:b0],a0):L.append(f'0x{i.address:08X}: {i.mnemonic} {i.op_str}')
  L += ['```','']
 L += ['## Interpretation boundary','','A candidate is not promoted merely for containing layout-sized constants. It must show coherent destination/source pointer arithmetic consistent with the closed 0x78C CtrlMultiAxis layout and then link to the Leica MCC path.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
