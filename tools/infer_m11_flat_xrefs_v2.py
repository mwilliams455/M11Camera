#!/usr/bin/env python3
"""Strengthen M11-P flat-image relocation inference with distributed strings.

Forensic-only. Input must be exact decompressed M11-P 2.6.1 firmware. Output is
address/statistical/disassembly metadata only; no proprietary firmware bytes.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import re
import struct
from pathlib import Path

EXPECTED_SHA="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
MASK32=0xffffffff
PRINTABLE=re.compile(rb"[\x20-\x7e]{20,}")

GROUPS={
 "leica_selector": b"(r2y) R2Y GAMMA already loaded",
 "milbeaut_driver": b"Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL",
}

KNOWN={
 "leica_selector":[
  b"(r2y) R2Y GAMMA already loaded",
  b"NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset",
  b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2",
  b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3",
  b"-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1",
  b"(r2y) R2Y YC already loaded",
  b"NO VALID STRING:  E_IMG_MACRO_DRV_R2Y_CATEGORY_YC_R2Y6A  img_macro_drv_r2y_select_yc_paraset YC",
  b"NO VALID STRING: E_IMG_MACRO_DRV_R2Y_CATEGORY_YBlend_R2Y6A  img_macro_drv_r2y_select_yc_paraset  BLEND",
  b"(r2y) R2Y ToneTable already loaded",
  b"NO VALID STRING   img_macro_drv_r2y_select_colorcorrection1_paraset",
 ],
 "milbeaut_driver":[
  b"Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL",
  b"Im_R2Y_Ctrl_Gamma error. pipe_no>D_IM_R2Y_PIPE12",
  b"Im_R2Y_Set_GammaTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
  b"Im_R2Y_Set_GammaYbTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
  b"Im_R2Y_Ctrl_CC1_Matrix error. r2y_ctrl_cc = NULL",
  b"Im_R2Y_Ctrl_Yc_Convert error. r2y_ctrl_ycc = NULL",
  b"Im_R2Y_Ctrl_Ynr error. r2y_ctrl_ynr = NULL",
  b"Im_R2Y_Ctrl_Color_NR error. r2y_ctrl_clpf = NULL",
  b"Im_R2Y_Ctrl_Chroma_Suppress error. r2y_ctrl_cs = NULL",
  b"Im_R2Y_Set_Gamma_Table error. tbl_index > 4",
 ],
}

def hits(data:bytes,n:bytes):
 out=[];p=0
 while True:
  p=data.find(n,p)
  if p<0:return out
  out.append(p);p+=1

def nearest_zero(data:bytes,c:int,d:int,limit=0x400000,min_run=256):
 pat=b'\0'*min_run
 p=data.rfind(pat,max(0,c-limit),c) if d<0 else data.find(pat,c,min(len(data),c+limit))
 if p<0:return None
 a=p;b=p+min_run
 while a>0 and data[a-1]==0:a-=1
 while b<len(data) and data[b]==0:b+=1
 return a,b

def region(data:bytes,c:int):
 a=nearest_zero(data,c,-1);b=nearest_zero(data,c,1)
 if not a or not b:raise ValueError('no zero-fill bounded raw region')
 return a[1],b[0]

def words(data:bytes,a:int,b:int):
 pos={};p=(a+3)&~3
 while p+4<=b:
  v=struct.unpack_from('<I',data,p)[0]
  if v not in pos:pos[v]=[]
  if len(pos[v])<12:pos[v].append(p)
  p+=4
 return pos,set(pos)

def unique_strings(data:bytes,a:int,b:int,maxn=80):
 cand=[]
 for m in PRINTABLE.finditer(data[a:b]):
  s=m.group();off=a+m.start()
  # Exact uniqueness across firmware reduces accidental shifted-block aliases.
  first=data.find(s)
  if first!=off or data.find(s,off+1)>=0:continue
  cand.append((off,s.decode('ascii',errors='replace')))
 if len(cand)<=maxn:return cand
 # Evenly distribute across the entire region rather than concentrating in one rodata cluster.
 idx=[]
 for i in range(maxn):idx.append(round(i*(len(cand)-1)/(maxn-1)))
 return [cand[i] for i in sorted(set(idx))]

def candidate_counts(wordset:set[int],targets:list[int]):
 c=collections.Counter()
 for t in targets:
  for v in wordset:c[(v-t)&MASK32]+=1
 return c

def support(wordset:set[int],targets:list[int],k:int):
 return [t for t in targets if ((t+k)&MASK32) in wordset]

def arm_refs(data:bytes,a:int,b:int,literal:int):
 out=[]
 p=(a+3)&~3
 while p+4<=b:
  w=struct.unpack_from('<I',data,p)[0]
  if ((w>>26)&3)==1 and ((w>>25)&1)==0 and ((w>>24)&1)==1 and ((w>>20)&1)==1 and ((w>>16)&15)==15:
   imm=w&0xfff;addr=p+8+imm if ((w>>23)&1) else p+8-imm
   if addr==literal:out.append((p,'ARM'))
  p+=4
 p=(a+1)&~1
 while p+2<=b:
  h=struct.unpack_from('<H',data,p)[0]
  if (h&0xf800)==0x4800 and (((p+4)&~3)+(h&0xff)*4)==literal:out.append((p,'Thumb16'))
  p+=2
 return out[:32]

def disasm(data:bytes,off:int,mode_name:str):
 try:
  from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 except Exception:return 'capstone unavailable'
 mode=(CS_MODE_THUMB if mode_name.startswith('Thumb') else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM,mode);lo=max(0,off-32);hi=min(len(data),off+72)
 ins=list(md.disasm(data[lo:hi],lo))
 return '; '.join(f'{i.address:#x}:{i.mnemonic} {i.op_str}' for i in ins[:28])

def one_group(data,name,anchor):
 ah=hits(data,anchor)
 if len(ah)!=1:return [f'### {name}','',f'anchor hit count={len(ah)}','']
 a,b=region(data,ah[0]);positions,wordset=words(data,a,b)
 auto=unique_strings(data,a,b,80)
 known=[]
 for n in KNOWN[name]:
  h=hits(data,n)
  if len(h)==1:known.append((h[0],n.decode('ascii',errors='replace')))
 # Solve with distributed strings. Keep candidates with strongest broad support.
 auto_off=[x[0] for x in auto]
 counts=candidate_counts(wordset,auto_off)
 raw=[]
 for k,n in counts.most_common(256):
  s=support(wordset,auto_off,k)
  if len(s)<3:break
  known_s=support(wordset,[x[0] for x in known],k)
  load=(a+k)&MASK32
  # ranking: distributed support first, known support second, page-aligned load base only as weak tie break
  raw.append((k,len(s),len(known_s),load,s,known_s))
 raw.sort(key=lambda x:(-x[1],-x[2],x[3]&0xfff!=0,x[3]&0xfff,x[0]))
 lines=[f'### {name}','',f'- raw region: `0x{a:08x}..0x{b:08x}` ({b-a} bytes)',f'- SHA-256: `{hashlib.sha256(data[a:b]).hexdigest()}`',f'- aligned unique words: `{len(wordset)}`',f'- distributed unique strings sampled: `{len(auto)}`',f'- known R2Y strings: `{len(known)}`','', 'Top relocation candidates:']
 if not raw:
  lines+=['- none supported by >=3 distributed strings',''];return lines
 label={o:s for o,s in known}
 for rank,(k,na,nk,load,sa,sk) in enumerate(raw[:10],1):
  lines.append(f'- #{rank}: `K=0x{k:08x}` load-base=`0x{load:08x}` distributed=`{na}/{len(auto)}` known=`{nk}/{len(known)}`')
  if rank<=3:
   for t in sk:
    ptr=(t+k)&MASK32;slots=positions.get(ptr,[])
    lines.append(f'  - known `{label[t]}` off `0x{t:08x}` -> runtime `0x{ptr:08x}` slots {", ".join(f"0x{x:08x}" for x in slots) or "none"}')
    for slot in slots[:4]:
     for roff,mode in arm_refs(data,a,b,slot)[:6]:
      lines.append(f'    - {mode} PC-relative literal xref candidate `0x{roff:08x}` -> slot `0x{slot:08x}`')
      lines.append(f'      - `{disasm(data,roff,mode)}`')
  lines.append('')
 # Show distribution of sampled target offsets, not proprietary text.
 lines.append('Distributed sample offset span:')
 if auto:lines.append(f'- `0x{auto[0][0]:08x}..0x{auto[-1][0]:08x}`')
 lines.append('')
 return lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected unpacked SHA {sha}')
 lines=['# M11-P flat relocation inference v2','',f'- exact unpacked SHA-256: `{sha}`','', '## Results','']
 for name,anchor in GROUPS.items():lines+=one_group(data,name,anchor)
 lines+=['## Interpretation boundary','', 'Prefer a relocation delta only when it explains many widely distributed unique strings. PC-relative loads are xref candidates, not automatically function identities. No renderer semantics are changed by this report.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(f'wrote {x.output}')
if __name__=='__main__':main()
