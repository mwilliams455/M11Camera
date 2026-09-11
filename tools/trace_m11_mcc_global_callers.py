#!/usr/bin/env python3
"""Whole-image caller scan for closed M11-P Im_R2Y_Ctrl_Multi_Axis.

Earlier caller probes intentionally searched only 0x01000000..0x02000000.
This probe removes that assumption and scans every aligned A32 instruction in
the exact unpacked image for B/BL targets to 0x01B2D324, plus whole-image
MOVW/MOVT constructions. It then bounds and disassembles each caller region.
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TARGET=0x01B2D324

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def branch_target(p,w):
 # A32 B/BL immediate. Exclude cond=0xF BLX-immediate encoding.
 if ((w>>25)&7)!=5 or ((w>>28)&0xF)==0xF:return None
 imm=w&0xffffff
 if imm&0x800000:imm-=1<<24
 return (p+8+(imm<<2))&0xffffffff
def mov_imm(w,kind):
 tag=w&0x0ff00000;want=0x03000000 if kind=='movw' else 0x03400000
 if tag!=want:return None
 return ((w>>12)&0xf),((((w>>16)&0xf)<<12)|(w&0xfff))
def is_push_lr(w):return (w&0xffff0000)==0xe92d0000 and bool(w&0x4000)
def is_return(w):return (((w&0xffff0000)==0xe8bd0000 and bool(w&0x8000)) or w==0xe12fff1e)
def bounds(d,call):
 lo=max(0,call-0x10000);fn=call
 for p in range(call-(call%4),lo,-4):
  if p+4<=len(d) and is_push_lr(u32(d,p)):fn=p;break
 end=min(len(d),fn+0x10000)
 for p in range(call+4-(call%4),end-3,4):
  if is_return(u32(d,p)):end=p+4;break
 return fn,end
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);c.skipdata=True;return c

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED_SHA:raise ValueError(h)
 branches=[];movpairs=[];stop=len(d)-4
 low=TARGET&0xffff;high=(TARGET>>16)&0xffff
 # Scan all four possible alignment phases because the unpacked image contains
 # mixed data/code sections and no assumption is made that every loaded section
 # starts on file offset phase zero. Branch candidates are subsequently judged
 # by caller disassembly quality.
 for phase in range(4):
  for p in range(phase,stop,4):
   w=u32(d,p);t=branch_target(p,w)
   if t==TARGET:branches.append((p,(w>>24)&1,phase))
   m=mov_imm(w,'movw')
   if m is not None and m[1]==low:
    rd=m[0]
    for q in range(p+4,min(p+32,stop),4):
     m2=mov_imm(u32(d,q),'movt')
     if m2==(rd,high):movpairs.append((p,q,rd,phase));break
 branches=sorted(set(branches));movpairs=sorted(set(movpairs))
 lines=['# M11-P global caller scan — Im_R2Y_Ctrl_Multi_Axis','',f'- unpacked SHA-256: `{h}`',f'- target: `0x{TARGET:08x}`',
        f'- whole-image A32 B/BL hits: `{[(hex(p),"BL" if link else "B",phase) for p,link,phase in branches]}`',
        f'- whole-image MOVW/MOVT address constructions: `{[(hex(p),hex(q),"r"+str(r),phase) for p,q,r,phase in movpairs]}`','']
 dec=md()
 for i,(p,link,phase) in enumerate(branches,1):
  fn,end=bounds(d,p)
  lines += [f'## Branch candidate {i} — `0x{p:08x}` {"BL" if link else "B"} phase {phase}','',f'- bounded function: `0x{fn:08x}..0x{end:08x}`','', '```asm']
  lo=max(fn,p-0x300);hi=min(end,p+0x300)
  for x in dec.disasm(d[lo:hi],lo):
   mark='  ; << target call' if x.address==p else ''
   lines.append(f'0x{x.address:08x}: {x.mnemonic} {x.op_str}{mark}')
  lines += ['```','']
 for i,(p,q,r,phase) in enumerate(movpairs,1):
  fn,end=bounds(d,p)
  lines += [f'## Pointer construction {i} — `0x{p:08x}`/`0x{q:08x}` r{r} phase {phase}','',f'- bounded function: `0x{fn:08x}..0x{end:08x}`','', '```asm']
  lo=max(fn,p-0x200);hi=min(end,q+0x300)
  for x in dec.disasm(d[lo:hi],lo):lines.append(f'0x{x.address:08x}: {x.mnemonic} {x.op_str}')
  lines += ['```','']
 lines += ['## Interpretation boundary','',
          'A raw branch hit is accepted as a real caller only when its surrounding instructions disassemble coherently as code and the argument setup is compatible with pipe number in r0 and CtrlMultiAxis pointer in r1.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(lines)+'\n');print(a.output)
if __name__=='__main__':main()
