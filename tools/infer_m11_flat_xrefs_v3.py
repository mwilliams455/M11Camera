#!/usr/bin/env python3
"""Efficient distributed-string relocation/xref inference for M11-P 2.6.1.

Forensic-only: exact decompressed firmware in, derived metadata out. No firmware
bytes are emitted. Candidate flat-image relocation deltas are seeded from widely
spaced unique strings and scored against all distributed strings, avoiding the
large cross-product Counter used by v2.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
MASK32=0xffffffff
PRINTABLE=re.compile(rb'[\x20-\x7e]{20,}')
GROUPS={
 'leica_selector':b'(r2y) R2Y GAMMA already loaded',
 'milbeaut_driver':b'Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL',
}
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
  b'(r2y) R2Y ToneTable already loaded',
  b'NO VALID STRING   img_macro_drv_r2y_select_colorcorrection1_paraset',
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

def hits(data,n):
 out=[];p=0
 while True:
  p=data.find(n,p)
  if p<0:return out
  out.append(p);p+=1

def fill(data,c,d,run=256,limit=0x400000):
 pat=b'\0'*run
 p=data.rfind(pat,max(0,c-limit),c) if d<0 else data.find(pat,c,min(len(data),c+limit))
 if p<0:return None
 a=p;b=p+run
 while a and data[a-1]==0:a-=1
 while b<len(data) and data[b]==0:b+=1
 return a,b

def region(data,c):
 a=fill(data,c,-1);b=fill(data,c,1)
 if not a or not b: raise RuntimeError('cannot bound raw region')
 return a[1],b[0]

def word_index(data,a,b):
 pos={};p=(a+3)&~3
 while p+4<=b:
  v=struct.unpack_from('<I',data,p)[0]
  pos.setdefault(v,[])
  if len(pos[v])<16:pos[v].append(p)
  p+=4
 return pos,set(pos)

def unique_distributed_strings(data,a,b,n=96):
 cand=[]
 for m in PRINTABLE.finditer(data[a:b]):
  raw=m.group();off=a+m.start()
  if data.find(raw)!=off or data.find(raw,off+1)>=0:continue
  cand.append((off,raw.decode('ascii',errors='replace')))
 if len(cand)<=n:return cand
 indexes=sorted(set(round(i*(len(cand)-1)/(n-1)) for i in range(n)))
 return [cand[i] for i in indexes]

def evenly(seq,n):
 if len(seq)<=n:return seq
 idx=sorted(set(round(i*(len(seq)-1)/(n-1)) for i in range(n)))
 return [seq[i] for i in idx]

def arm_literal_refs(data,a,b,literal):
 out=[];p=(a+3)&~3
 while p+4<=b:
  w=struct.unpack_from('<I',data,p)[0]
  if ((w>>26)&3)==1 and not((w>>25)&1) and ((w>>24)&1) and ((w>>20)&1) and ((w>>16)&15)==15:
   imm=w&0xfff;addr=p+8+imm if ((w>>23)&1) else p+8-imm
   if addr==literal:out.append((p,'ARM'))
  p+=4
 p=(a+1)&~1
 while p+2<=b:
  h=struct.unpack_from('<H',data,p)[0]
  if (h&0xf800)==0x4800 and (((p+4)&~3)+(h&0xff)*4)==literal:out.append((p,'Thumb16'))
  p+=2
 return out[:48]

def disasm(data,off,mode_name):
 try:
  from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 except Exception:return 'capstone unavailable'
 md=Cs(CS_ARCH_ARM,(CS_MODE_THUMB if mode_name.startswith('Thumb') else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN)
 lo=max(0,off-32);hi=min(len(data),off+80)
 return '; '.join(f'{i.address:#x}:{i.mnemonic} {i.op_str}' for i in list(md.disasm(data[lo:hi],lo))[:30])

def solve(wordset,targets,seeds):
 # candidate K values are generated only from seed target -> existing aligned word.
 candidates=set()
 for t in seeds:
  for v in wordset:candidates.add((v-t)&MASK32)
 ranked=[]
 for k in candidates:
  sup=[t for t in targets if ((t+k)&MASK32) in wordset]
  if len(sup)>=3:ranked.append((len(sup),k,sup))
 ranked.sort(key=lambda x:(-x[0],x[1]))
 return ranked[:32]

def group(data,name,anchor):
 hh=hits(data,anchor)
 if len(hh)!=1:return [f'### {name}','',f'- anchor hits: {len(hh)}','']
 a,b=region(data,hh[0]);positions,wordset=word_index(data,a,b)
 auto=unique_distributed_strings(data,a,b,96)
 targets=[x[0] for x in auto]
 seeds=[x[0] for x in evenly(auto,8)]
 known=[]
 for n in KNOWN[name]:
  h=hits(data,n)
  if len(h)==1:known.append((h[0],n.decode('ascii',errors='replace')))
 ranked=solve(wordset,targets,seeds)
 known_offsets=[x[0] for x in known]
 label={o:s for o,s in known}
 # Re-rank top candidates with known-string support as secondary criterion.
 scored=[]
 for na,k,sup in ranked:
  ks=[t for t in known_offsets if ((t+k)&MASK32) in wordset]
  scored.append((na,len(ks),k,sup,ks))
 scored.sort(key=lambda x:(-x[0],-x[1],((a+x[2])&MASK32)&0xfff!=0,x[2]))
 lines=[f'### {name}','',f'- raw region: `0x{a:08x}..0x{b:08x}` ({b-a} bytes)',f'- region SHA-256: `{hashlib.sha256(data[a:b]).hexdigest()}`',f'- aligned unique words: `{len(wordset)}`',f'- distributed unique strings: `{len(auto)}`',f'- seed strings: `{len(seeds)}`',f'- known R2Y strings: `{len(known)}`','', 'Top candidates:']
 if not scored:
  lines+=['- no relocation delta explains >=3 distributed strings',''];return lines
 for rank,(na,nk,k,sup,ks) in enumerate(scored[:10],1):
  load=(a+k)&MASK32
  lines.append(f'- #{rank}: `K=0x{k:08x}` implied-load=`0x{load:08x}` distributed=`{na}/{len(auto)}` known=`{nk}/{len(known)}`')
  if rank<=3:
   for t in ks:
    ptr=(t+k)&MASK32;slots=positions.get(ptr,[])
    lines.append(f'  - `{label[t]}` -> runtime `0x{ptr:08x}`; literal slots: {", ".join(f"0x{x:08x}" for x in slots) or "none"}')
    for slot in slots[:4]:
     for roff,mode in arm_literal_refs(data,a,b,slot)[:6]:
      lines.append(f'    - {mode} xref candidate `0x{roff:08x}` -> literal `0x{slot:08x}`')
      lines.append(f'      - `{disasm(data,roff,mode)}`')
  lines.append('')
 if auto:lines += [f'- distributed sample spans `0x{auto[0][0]:08x}..0x{auto[-1][0]:08x}`','']
 return lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected SHA {sha}')
 lines=['# M11-P flat relocation inference v3','',f'- exact unpacked SHA-256: `{sha}`','', '## Results','']
 for name,anchor in GROUPS.items():lines+=group(data,name,anchor)
 lines += ['## Interpretation boundary','', 'Only a delta with broad support across widely distributed unique strings should be treated as a plausible flat-image relocation. ARM/Thumb literal-load hits are xref candidates requiring control-flow validation. This report does not alter renderer semantics.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(f'wrote {x.output}')
if __name__=='__main__':main()
