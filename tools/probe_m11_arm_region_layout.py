#!/usr/bin/env python3
"""Classify ARM-text vs data layout in M11-P R2Y raw regions.

External Milbeaut build evidence targets Cortex-A7, little-endian, ARM state,
Ofast.  This exact-firmware probe therefore scores 4 KiB buckets for common ARM
code signatures (function prologue/epilogue, BL, PC-literal LDR, BX LR).  It
emits only derived counts/addresses and short disassembly metadata, never bytes.
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
REGIONS={
 'leica_selector':(0x02779c8c,0x027ec9bb,0x02788914),
 'milbeaut_driver':(0x030b3408,0x03100868,0x030d0dac),
}

def classify(w):
 out=[]
 if (w & 0xffff0000)==0xe92d0000: out.append('push')
 if (w & 0xffff0000)==0xe8bd0000: out.append('pop')
 if w==0xe12fff1e: out.append('bx_lr')
 if (w & 0xffff0000) in (0xe59f0000,0xe51f0000): out.append('ldr_pc')
 if (w & 0xff000000)==0xeb000000: out.append('bl')
 return out

def disasm(data,off,n=20):
 try:
  from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
 except Exception:return 'capstone unavailable'
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
 ins=list(md.disasm(data[off:off+4*n],off,count=n))
 return '; '.join(f'{i.address:#x}:{i.mnemonic} {i.op_str}' for i in ins)

def analyze(data,name,a,b,target):
 bucket=0x1000
 rows=[]; totals={'push':0,'pop':0,'bx_lr':0,'ldr_pc':0,'bl':0}
 for bs in range(a&~(bucket-1),b,bucket):
  be=min(b,bs+bucket); c={k:0 for k in totals}; pro=[]
  p=max(a,(bs+3)&~3)
  while p+4<=be:
   w=struct.unpack_from('<I',data,p)[0]
   for k in classify(w):
    c[k]+=1; totals[k]+=1
    if k=='push' and len(pro)<5:pro.append(p)
   p+=4
  # BL and literal loads are weighted lower because random data can resemble them.
  score=8*c['push']+6*c['pop']+8*c['bx_lr']+2*c['ldr_pc']+c['bl']
  rows.append((score,bs,be,c,pro))
 rows.sort(reverse=True)
 lines=[f'### {name}','',f'- region `0x{a:08x}..0x{b:08x}`',f'- diagnostic target `0x{target:08x}`',f"- totals push={totals['push']} pop={totals['pop']} bx_lr={totals['bx_lr']} ldr_pc={totals['ldr_pc']} bl={totals['bl']}",'', 'Top code-like 4 KiB buckets:']
 for score,bs,be,c,pro in rows[:20]:
  dist=0 if bs<=target<be else min(abs(target-bs),abs(target-be))
  lines.append(f"- `0x{bs:08x}..0x{be:08x}` score `{score}` distance-to-target `{dist:#x}` push={c['push']} pop={c['pop']} bx={c['bx_lr']} ldrpc={c['ldr_pc']} bl={c['bl']}")
  for po in pro[:2]:lines.append(f'  - prologue candidate `0x{po:08x}` — `{disasm(data,po)}`')
 lines += ['', 'Nearest strict ARM prologue candidates to diagnostic target:']
 pros=[]
 p=(a+3)&~3
 while p+4<=b:
  w=struct.unpack_from('<I',data,p)[0]
  if (w&0xffff0000)==0xe92d0000:pros.append(p)
  p+=4
 for po in sorted(pros,key=lambda x:abs(x-target))[:20]:
  lines.append(f'- `0x{po:08x}` delta `{po-target:+#x}` — `{disasm(data,po,12)}`')
 lines.append('')
 return lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected SHA {sha}')
 lines=['# M11-P ARM region-layout probe','',f'- exact unpacked SHA-256 `{sha}`','', '## Results','']
 for n,(a,b,t) in REGIONS.items():lines+=analyze(data,n,a,b,t)
 lines += ['## Interpretation boundary','', 'Opcode-density scoring only distinguishes code-like from data-like areas. Individual decodes can be accidental; a function identity requires coherent control flow and corroborating constants/xrefs.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(x.output)
if __name__=='__main__':main()
