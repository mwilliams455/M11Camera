#!/usr/bin/env python3
"""Independently solve pointer relocation for the M11 R2Y CLPF/CSP selector family.

The previous Cat42 xref pass intentionally used the already-established Leica
R2Y data relocation and found no direct full-address references. This probe does
not assume that delta. Instead it requires a candidate anchor pointer to preserve
exact pairwise spacing across eleven unique neighboring selector strings. If no
candidate survives, that is evidence for base-relative/PIC addressing rather
than a different simple relocation.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
import numpy as np

EXPECTED_SHA="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
MASK32=0xffffffff
TARGETS=[
 b"(r2y) R2Y CHROMA LPF already loaded",
 b"NO VALID STRING:  E_IMG_MACRO_DRV_R2Y_CATEGORY_CLPF_R2Y6A  img_macro_drv_r2y_select_chroma_dif_lpf_paraset",
 b"Dependency.Iso:%d   DngReso:%d",
 b"----ERROR-----   img_macro_drv_r2y_select_chroma_dif_lpf_paraset 1",
 b"(r2y) R2Y CHROMA SUPPRESS already loaded",
 b"NO VALID STRING ->  E_IMG_MACRO_DRV_R2Y_CATEGORY_CsCo_R2Y6A  img_macro_drv_r2y_select_chroma_suppress_paraset",
 b"Dependency.Iso:%d   Saturation:%d",
 b"----ERROR-----   img_macro_drv_r2y_select_chroma_suppress_paraset 1",
 b"(r2y) R2Y POSTPROCESSING EDGE ENHANCEMENT already loaded",
 b"NO VALID STRING   img_macro_drv_r2y_select_postprcessing_edge_enhancment_paraset EE0",
 b"Dependency.MacroMode:%d   Iso:%d",
 b"----ERROR-----   img_macro_drv_r2y_select_postprcessing_edge_enhancment_paraset 1",
]

def unique_hit(d,n):
 p=d.find(n)
 if p<0 or d.find(n,p+1)>=0:raise ValueError(f'non-unique target {n!r}')
 return p

def contains_sorted(a,v):
 idx=np.searchsorted(a,v);ok=idx<a.size;out=np.zeros(v.shape,dtype=bool)
 if np.any(ok):
  ii=idx[ok];out[ok]=a[ii]==v[ok]
 return out

def a32_lit_xrefs(d,slot):
 out=[];lo=max(0,slot-0x1010)&~3;hi=min(len(d)-4,slot+0x1010)
 for p in range(lo,hi+1,4):
  w=struct.unpack_from('<I',d,p)[0]
  if ((w>>28)&15)!=15 and ((w>>26)&3)==1 and not((w>>25)&1) and ((w>>24)&1) and not((w>>21)&1) and ((w>>20)&1) and ((w>>16)&15)==15:
   imm=w&0xfff;eff=p+8+(imm if ((w>>23)&1) else -imm)
   if eff==slot:out.append(p)
 return out

def thumb16_lit_xrefs(d,slot):
 out=[];lo=max(0,slot-0x410)&~1;hi=min(len(d)-2,slot+0x410)
 for p in range(lo,hi+1,2):
  h=struct.unpack_from('<H',d,p)[0]
  if (h&0xf800)==0x4800:
   eff=((p+4)&~3)+(h&0xff)*4
   if eff==slot:out.append(p)
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();sha=hashlib.sha256(d).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(sha)
 offs=[unique_hit(d,n) for n in TARGETS];anchor=offs[0]
 aligned=len(d)&~3;words=np.frombuffer(memoryview(d)[:aligned],dtype='<u4');uniq=np.unique(words)
 cand=uniq.copy();progress=[]
 for t in offs[1:]:
  diff=np.uint64((t-anchor)&MASK32);expected=((cand.astype(np.uint64)+diff)&MASK32).astype(np.uint32)
  cand=cand[contains_sorted(uniq,expected)];progress.append((t,int(cand.size)))
  if cand.size==0:break
 lines=['# M11-P Cat42 selector-family independent relocation solve','',f'- SHA-256: `{sha}`',f'- unique strings: `{len(offs)}`',f'- raw span: `0x{min(offs):08x}..0x{max(offs):08x}`',f'- globally unique aligned u32 values: `{uniq.size}`','', '## Constraint progression','']
 for t,n in progress:lines.append(f'- through raw target `0x{t:08x}`: `{n}` candidate anchor pointer(s)')
 lines += ['',f'- final common pointer candidates: **{int(cand.size)}**','']
 for pv in cand[:32]:
  p0=int(pv);delta=(p0-anchor)&MASK32
  lines += [f'## Candidate anchor `0x{p0:08x}` / delta `0x{delta:08x}`','']
  support=0
  for t,n in zip(offs,TARGETS):
   v=(t+delta)&MASK32;idx=np.flatnonzero(words==np.uint32(v));slots=[int(x)*4 for x in idx[:12]]
   if slots:support+=1
   label=n.decode('ascii','replace')[:70]
   lines.append(f'- `{label}` raw `0x{t:08x}` -> ptr `0x{v:08x}` slots `{len(idx)}`')
   for s in slots[:4]:
    ar=a32_lit_xrefs(d,s);th=thumb16_lit_xrefs(d,s)
    lines.append(f'  - slot `0x{s:08x}`: A32 LDR `{len(ar)}`; Thumb16 LDR `{len(th)}`; refs `{[hex(x) for x in (ar+th)[:12]]}`')
  lines.append(f'- strings with pointer slots: `{support}/{len(offs)}`')
  lines.append('')
 lines += ['## Interpretation boundary','', 'A surviving candidate that preserves all independent string spacings is strong evidence for a simple relocation family. If the candidate set collapses to zero after several strings, the selector code does not store full pointers to this family under one affine delta and base-relative/PIC reconstruction should be preferred.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(lines)+'\n');print(a.output)
if __name__=='__main__':main()
