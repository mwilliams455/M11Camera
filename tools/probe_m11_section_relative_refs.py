#!/usr/bin/env python3
"""Probe section-relative string references in exact M11-P 2.6.1 raw R2Y code regions.

The matching Milbeaut sources target little-endian Cortex-A7 ARM with GCC.  The
M11 raw selector/driver regions do not support one simple absolute relocation
base and do not expose direct ADR references.  This helper therefore tests a
relocatable-module hypothesis: aligned words may hold offsets/addends relative
to one or more section bases.

Output is derived metadata only; no firmware bytes are emitted.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from collections import Counter, defaultdict
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
REGIONS={
 'leica_selector':(0x02779c8c,0x027ec9bb),
 'milbeaut_driver':(0x030b3408,0x03100868),
}
PRINTABLE=re.compile(rb'[\x20-\x7e]{16,}\x00')
KNOWN={
 'leica_selector':[
  b'(r2y) R2Y GAMMA already loaded',
  b'NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset',
  b'---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2',
  b'---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3',
  b'-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1',
  b'(r2y) R2Y YC already loaded',
  b'NO VALID STRING:  E_IMG_MACRO_DRV_R2Y_CATEGORY_YC_R2Y6A  img_macro_drv_r2y_select_yc_paraset YC',
  b'NO VALID STRING: E_IMG_MACRO_DRV_R2Y_CATEGORY_YBlend_R2Y6A  img_macro_drv_r2y_select_yc_paraset  BLEND',
 ],
 'milbeaut_driver':[
  b'Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL',
  b'Im_R2Y_Ctrl_Gamma error. pipe_no>D_IM_R2Y_PIPE12',
  b'Im_R2Y_Set_GammaTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12',
  b'Im_R2Y_Set_GammaYbTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12',
  b'Im_R2Y_Ctrl_CC1_Matrix error. r2y_ctrl_cc = NULL',
  b'Im_R2Y_Ctrl_Yc_Convert error. r2y_ctrl_ycc = NULL',
  b'Im_R2Y_Ctrl_Ynr error. r2y_ctrl_ynr = NULL',
  b'Im_R2Y_Ctrl_Color_NR error. r2y_ctrl_clpf = NULL',
  b'Im_R2Y_Ctrl_Chroma_Suppress error. r2y_ctrl_cs = NULL',
  b'Im_R2Y_Set_Gamma_Table error. tbl_index > 4',
 ],
}

def one_hit(data,n):
 p=data.find(n)
 return p if p>=0 and data.find(n,p+1)<0 else None

def sample_strings(data,a,b,maxn=120):
 rows=[]
 for m in PRINTABLE.finditer(data[a:b]):
  raw=m.group()[:-1]
  off=a+m.start()
  if len(raw)>=16 and data.find(raw)==off and data.find(raw,off+1)<0:
   rows.append((off,raw.decode('ascii',errors='replace')))
 if len(rows)<=maxn:return rows
 # evenly distributed across the raw region
 return [rows[round(i*(len(rows)-1)/(maxn-1))] for i in range(maxn)]

def aligned_words(data,a,b):
 out=[]
 p=(a+3)&~3
 while p+4<=b:
  out.append((p,struct.unpack_from('<I',data,p)[0]))
  p+=4
 return out

def analyze(data,name,a,b):
 strings=sample_strings(data,a,b)
 words=aligned_words(data,a,b)
 # Candidate base = target_abs - stored_u32.  Keep bases plausibly local to
 # this raw module and aligned; this rejects arbitrary 32-bit word aliases.
 counter=Counter(); examples=defaultdict(list)
 lo=a-0x200000; hi=b+0x200000
 for soff,text in strings:
  for woff,w in words:
   base=soff-w
   if lo<=base<=hi and (base&3)==0:
    counter[base]+=1
    if len(examples[base])<8: examples[base].append((soff,woff,w,text[:80]))
 top=counter.most_common(20)
 lines=[f'### {name}','',f'- raw region `0x{a:08x}..0x{b:08x}`',f'- sampled distributed unique strings `{len(strings)}`',f'- aligned words `{len(words)}`','', 'Top plausible local section bases:']
 if not top: lines.append('- none')
 for base,count in top:
  lines.append(f'- base `0x{base:08x}` support `{count}/{len(strings)}` delta-from-region-start `{base-a:+#x}`')
  for soff,woff,w,text in examples[base]:
   lines.append(f'  - str `0x{soff:08x}` word `0x{woff:08x}` stored `0x{w:08x}` — `{text}`')
 # Exact known-target checks at the top bases.
 lines += ['', 'Known R2Y strings under top bases:']
 for needle in KNOWN[name]:
  t=one_hit(data,needle); label=needle.decode('ascii',errors='replace')
  if t is None:
   lines.append(f'- `{label}`: not unique'); continue
  hits=[]
  for base,_ in top[:12]:
   expected=t-base
   if not (0<=expected<=0xffffffff):continue
   for woff,w in words:
    if w==expected:hits.append((base,woff,w))
  lines.append(f'- `{label}` target `0x{t:08x}` matches `{len(hits)}`')
  for base,woff,w in hits[:12]:lines.append(f'  - base `0x{base:08x}` word `0x{woff:08x}` stored `0x{w:08x}`')
 lines.append('')
 return lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected SHA {sha}')
 lines=['# M11-P section-relative reference probe','',f'- exact unpacked SHA-256 `{sha}`','', '## Results','']
 for n,(a,b) in REGIONS.items():lines+=analyze(data,n,a,b)
 lines += ['## Interpretation boundary','', 'A repeated local base is evidence for section-relative/addend references only when it explains many widely distributed unique strings and preferably known R2Y diagnostics. Isolated matches are not consumer xrefs.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(x.output)
if __name__=='__main__':main()
