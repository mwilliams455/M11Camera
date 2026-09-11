#!/usr/bin/env python3
"""Find IQ-bin / MCC builder anchors for the dynamic M11-P multi-axis object.

The full 0x78c CtrlMultiAxis object is not present as a static blob beginning
with Leica's known MCYC basis. Public Milbeaut lineage names the producer
`iq_bin_r2y_axis_ctrl_multi_axis` and related MCC1 logic. This probe searches
the exact Leica image for semantic strings and compact code/data constants that
can anchor the dynamic builder without assuming those public names survived.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TERMS=(b'iqbin',b'iq_bin',b'mcc',b'multi_axis',b'multi axis',b'r2y_axis',b'axis_mcc',b'v0121',b'ctrl_multi',b'color correction',b'colour correction')
CONSTANTS=(0x78c,0x762,0x492,0x5a,1932,1890,1170,90)

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def mov_imm(w,kind):
 tag=w&0x0FF00000; want=0x03000000 if kind=='movw' else 0x03400000
 if tag!=want:return None
 return ((w>>12)&0xF),((((w>>16)&0xF)<<12)|(w&0xFFF))
def strings(d,minlen=5): return [(m.start(),m.group()) for m in re.finditer(rb'[ -~]{%d,}'%minlen,d)]
def find_all(d,n):
 out=[];p=0
 while True:
  p=d.find(n,p)
  if p<0:return out
  out.append(p);p+=1

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED_SHA:raise ValueError(h)
 ss=strings(d)
 semantic=[]
 for p,s in ss:
  low=s.lower()
  hits=[t.decode() for t in TERMS if t in low]
  if hits: semantic.append((p,s,hits))

 # Raw little-endian 32-bit constants and ARM MOVW immediate loads in code.
 raw={}; mov={}
 for c in CONSTANTS:
  raw[c]=find_all(d,struct.pack('<I',c))[:500]
  vv=[]
  for p in range(0x01000000,min(0x02000000,len(d))-4,4):
   x=mov_imm(u32(d,p),'movw')
   if x and x[1]==(c&0xffff): vv.append((p,x[0]))
  mov[c]=vv[:1000]

 lines=['# M11-P dynamic MCC / IQ-builder anchor scan','',f'- unpacked SHA-256: `{h}`','', '## Semantic strings','']
 for p,s,hits in semantic:
  lines.append(f'- `0x{p:08x}` terms `{hits}` `{s.decode("ascii","replace")}`')
 if not semantic:lines.append('- none')
 lines += ['','## CtrlMultiAxis-layout constants','']
 for c in CONSTANTS:
  lines += [f'### `{c}` / `0x{c:x}`',f'- raw u32 occurrences: `{[hex(x) for x in raw[c][:100]]}`',f'- ARM MOVW occurrences: `{[(hex(p),"r"+str(r)) for p,r in mov[c][:100]]}`','']

 # String neighborhoods around the most useful terms, de-duplicated by 1KB windows.
 anchors=[(p,s,hits) for p,s,hits in semantic if any(t in hits for t in ('iqbin','iq_bin','mcc','r2y_axis','axis_mcc','v0121'))]
 windows=[]
 for p,_,_ in anchors:
  lo=max(0,p-0x500);hi=min(len(d),p+0x500)
  if any(abs(p-q)<0x800 for q,_,_ in windows):continue
  windows.append((p,lo,hi))
 lines += ['','## Semantic anchor neighborhoods','']
 for p,lo,hi in windows[:50]:
  lines += [f'### around `0x{p:08x}`','']
  for q,s in ss:
   if lo<=q<=hi:lines.append(f'- `0x{q:08x}` `{s.decode("ascii","replace")}`')
  lines.append('')
 lines += ['## Interpretation boundary','',
          'These are navigation anchors only. Public IQ-bin names do not prove Leica uses the same producer. A dynamic builder is accepted only after Leica code/data flow is traced into the closed 0x78c CtrlMultiAxis ABI.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(lines)+'\n');print(a.output)
if __name__=='__main__':main()
