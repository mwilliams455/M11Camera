#!/usr/bin/env python3
"""Trace the upstream source/ABI for the closed Leica M11-P MCC writer.

The hardware writer is already closed at 0x01B2D324..0x01B60320. This tool
keeps renderer code untouched and asks only: how is the writer invoked, where
is its CtrlMultiAxis-like source object, and what source-address arithmetic
feeds each public MCC family?
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
ENTRY=0x01B2D324; END=0x01B60320
FAMILY_FIRST={
 'MCYC':0x01B2D494,'MCB':0x01B2DA90,'MCID':0x01B2E238,
 'MCKA':0x01B2E358,'MCKB':0x01B306DC,'MCKC':0x01B32C08,'MCKD':0x01B35240,
 'MCKE':0x01B37888,'MCKF':0x01B3A094,'MCKG':0x01B3CA8C,'MCKH':0x01B3F508,
 'MCKI':0x01B41F88,'MCKJ':0x01B449A0,'MCKK':0x01B472C4,'MCKL':0x01B49D5C,
 'MCLA':0x01B4C7FC,'MCLB':0x01B4E1B4,'MCLC':0x01B4FB58,'MCLD':0x01B51510,
 'MCLE':0x01B52E00,'MCLF':0x01B546C4,'MCLG':0x01B55FC8,'MCLH':0x01B5793C,
 'MCLI':0x01B592E4,'MCLJ':0x01B5AC9C,'MCLK':0x01B5C640,'MCLL':0x01B5DFF8,
 'BLEND':0x01B5F9CC,
}

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.skipdata=True; return c

def branch_target(p,w):
 if ((w>>25)&7)!=5 or ((w>>28)&0xF)==0xF: return None
 imm=w&0xFFFFFF
 if imm&0x800000: imm-=1<<24
 return (p+8+(imm<<2))&0xFFFFFFFF

def mov_imm(w,kind):
 # ARM A1 MOVW/MOVT immediate form.
 tag=w & 0x0FF00000; want=0x03000000 if kind=='movw' else 0x03400000
 if tag!=want: return None
 rd=(w>>12)&0xF; imm=(((w>>16)&0xF)<<12)|(w&0xFFF)
 return rd,imm

def dis(d,lo,hi): return list(md().disasm(d[lo:hi],lo))
def excerpt(d,center,before=0x100,after=0x30):
 lo=max(ENTRY,center-before); lo=(lo+3)&~3; hi=min(END,center+after)
 return dis(d,lo,hi)

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED_SHA: raise ValueError(h)

 needle=struct.pack('<I',ENTRY); refs=[]; p=0
 while True:
  p=d.find(needle,p)
  if p<0: break
  refs.append(p); p+=1

 branches=[]
 lo=0x01000000; hi=min(0x02000000,len(d))
 for p in range(lo,hi-4,4):
  t=branch_target(p,u32(d,p))
  if t==ENTRY: branches.append((p,(u32(d,p)>>24)&1))

 # Raw ARM MOVW/MOVT scan for the exact entry pointer; no full-window Capstone pass.
 movpairs=[]
 for p in range(lo,hi-4,4):
  a0=mov_imm(u32(d,p),'movw')
  if a0 is None or a0[1] != (ENTRY & 0xFFFF): continue
  rd=a0[0]
  for q in range(p+4,min(p+32,hi),4):
   a1=mov_imm(u32(d,q),'movt')
   if a1==(rd,(ENTRY>>16)&0xFFFF):
    movpairs.append((p,q,rd)); break

 lines=['# M11-P MCC writer upstream/source trace','',f'- unpacked SHA-256: `{h}`',f'- writer: `0x{ENTRY:08x}..0x{END:08x}`',
        f'- raw little-endian entry-address references: `{[hex(x) for x in refs]}`',
        f'- direct ARM B/BL references: `{[(hex(p),"BL" if link else "B") for p,link in branches]}`',
        f'- MOVW/MOVT entry-address constructions: `{[(hex(a),hex(b),"r"+str(r)) for a,b,r in movpairs]}`','']

 lines += ['## Writer prologue','', '```asm']
 for x in dis(d,ENTRY,min(ENTRY+0x300,END)): lines.append(f'0x{x.address:08x}: {x.mnemonic} {x.op_str}')
 lines += ['```','', '## Writer epilogue','', '```asm']
 for x in dis(d,max(ENTRY,END-0x300),END): lines.append(f'0x{x.address:08x}: {x.mnemonic} {x.op_str}')
 lines += ['```','']

 if refs:
  lines += ['## Raw entry-pointer reference neighborhoods','']
  for r in refs:
   rlo=max(0,r-64); rhi=min(len(d),r+68); words=[]
   for q in range(rlo+(4-rlo%4)%4,rhi-3,4): words.append(f'0x{q:08x}: 0x{u32(d,q):08x}')
   lines += [f'### reference at `0x{r:08x}`','', '```text',*words,'```','']

 lines += ['## First hardware write of each MCC family: source-address context','']
 for name,addr in FAMILY_FIRST.items():
  lines += [f'### {name} — first hardware write `0x{addr:08x}`','', '```asm']
  for x in excerpt(d,addr,0x120,0x20):
   mark='  ; << hardware write' if x.address==addr else ''
   lines.append(f'0x{x.address:08x}: {x.mnemonic} {x.op_str}{mark}')
  lines += ['```','']

 lines += ['## Interpretation boundary','',
  'The closed hardware writer must remain separate from the still-open upstream coefficient-source question. A source-object identity is accepted only when entry ABI / pointer references and field-offset progression agree with the public CtrlMultiAxis layout.','']
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
