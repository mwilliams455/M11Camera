#!/usr/bin/env python3
"""Trace relocation-independent references to M11-P R2Y diagnostic strings.

The selector/driver regions do not support a simple stored absolute-pointer
relocation model. This forensic helper therefore looks for references whose
semantics survive relocation unchanged:

* ARM/A32 ADR (ADD/SUB PC-relative immediate),
* Thumb16 ADR,
* Capstone-decoded ARM/Thumb/AArch64 ADR forms,
* signed 32-bit relative words where slot(+bias)+disp == target.

Input is hash-gated exact decompressed M11-P 2.6.1 firmware. Output contains only
derived offsets/disassembly text and never firmware bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'

TARGETS={
 'leica':[
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
 'driver':[
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
ANCHORS={'leica':TARGETS['leica'][0],'driver':TARGETS['driver'][0]}

def hits(data,n):
 out=[];p=0
 while True:
  p=data.find(n,p)
  if p<0:return out
  out.append(p);p+=1

def zero_fill(data,c,d,run=256,limit=0x400000):
 pat=b'\0'*run
 p=data.rfind(pat,max(0,c-limit),c) if d<0 else data.find(pat,c,min(len(data),c+limit))
 if p<0:return None
 a=p;b=p+run
 while a and data[a-1]==0:a-=1
 while b<len(data) and data[b]==0:b+=1
 return a,b

def region(data,c):
 a=zero_fill(data,c,-1);b=zero_fill(data,c,1)
 if not a or not b:raise RuntimeError('raw region boundaries not found')
 return a[1],b[0]

def ror32(x,n):
 n&=31
 return ((x>>n)|(x<<(32-n)))&0xffffffff if n else x&0xffffffff

def a32_adr_refs(data,start,end,target):
 out=[]
 p=(start+3)&~3
 while p+4<=end:
  w=struct.unpack_from('<I',data,p)[0]
  # cond != 1111; data-processing immediate; S=0; Rn=PC; opcode ADD(4)/SUB(2)
  cond=(w>>28)&0xf; opcode=(w>>21)&0xf
  if cond!=0xf and ((w>>25)&0x7)==0x1 and ((w>>20)&1)==0 and ((w>>16)&0xf)==0xf and opcode in (2,4):
   imm=ror32(w&0xff,2*((w>>8)&0xf));base=p+8
   dst=(base+imm)&0xffffffff if opcode==4 else (base-imm)&0xffffffff
   if dst==target:out.append((p,'A32 ADR/addsub'))
  p+=4
 return out

def thumb16_adr_refs(data,start,end,target):
 out=[];p=(start+1)&~1
 while p+2<=end:
  h=struct.unpack_from('<H',data,p)[0]
  if (h&0xf800)==0xa000:
   dst=(((p+4)&~3)+((h&0xff)<<2))&0xffffffff
   if dst==target:out.append((p,'Thumb16 ADR'))
  p+=2
 return out

def capstone_adr_refs(data,start,end,target):
 out=[]
 try:
  from capstone import Cs,CS_ARCH_ARM,CS_ARCH_ARM64,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
  from capstone.arm import ARM_OP_IMM
  from capstone.arm64 import ARM64_OP_IMM
 except Exception:return out
 # Restrict decode search to a useful local radius: ADR immediates are local by design.
 lo=max(start,target-0x200000);hi=min(end,target+0x200000)
 configs=[('ARM',CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,4,ARM_OP_IMM),('THUMB',CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN,2,ARM_OP_IMM),('AArch64',CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,4,ARM64_OP_IMM)]
 for name,arch,mode,step,immtype in configs:
  md=Cs(arch,mode);md.detail=True
  p=(lo+(step-1))&~(step-1)
  while p+4<=hi:
   ins=list(md.disasm(data[p:p+4],p,count=1))
   if ins:
    i=ins[0]
    if i.mnemonic.lower()=='adr' and i.operands and i.operands[-1].type==immtype:
     if (int(i.operands[-1].imm)&0xffffffff)==target:
      out.append((p,f'{name} Capstone ADR'))
   p+=step
 return out

def relative_word_refs(data,start,end,target):
 out=[];p=(start+3)&~3
 while p+4<=end:
  s=struct.unpack_from('<i',data,p)[0]
  for bias in (0,4,8):
   if p+bias+s==target:
    out.append((p,bias,s))
  p+=4
 return out

def disasm_context(data,off,kind):
 try:
  from capstone import Cs,CS_ARCH_ARM,CS_ARCH_ARM64,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 except Exception:return 'capstone unavailable'
 if 'AArch64' in kind:arch=CS_ARCH_ARM64;mode=CS_MODE_LITTLE_ENDIAN;align=4
 elif 'Thumb' in kind:arch=CS_ARCH_ARM;mode=CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN;align=2
 else:arch=CS_ARCH_ARM;mode=CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN;align=4
 lo=max(0,off-40);lo=lo&~(align-1);hi=min(len(data),off+88)
 md=Cs(arch,mode)
 ins=list(md.disasm(data[lo:hi],lo))
 return '; '.join(f'{i.address:#x}:{i.mnemonic} {i.op_str}' for i in ins[:40])

def group(data,name):
 ah=hits(data,ANCHORS[name])
 if len(ah)!=1:return [f'### {name}','',f'- anchor hit count `{len(ah)}`','']
 a,b=region(data,ah[0])
 lines=[f'### {name}','',f'- raw region `0x{a:08x}..0x{b:08x}`',f'- SHA-256 `{hashlib.sha256(data[a:b]).hexdigest()}`','']
 for needle in TARGETS[name]:
  hh=hits(data,needle);label=needle.decode('ascii',errors='replace')
  lines.append(f'#### `{label}`')
  if len(hh)!=1:
   lines += [f'- hit count `{len(hh)}`',''];continue
  t=hh[0];lines.append(f'- target `0x{t:08x}`')
  direct=a32_adr_refs(data,a,b,t)+thumb16_adr_refs(data,a,b,t)+capstone_adr_refs(data,a,b,t)
  # de-duplicate same address/mode-family results
  seen=set();ded=[]
  for x in direct:
   key=(x[0],x[1])
   if key not in seen:seen.add(key);ded.append(x)
  lines.append(f'- direct PC-relative ADR candidates `{len(ded)}`')
  for off,kind in ded[:24]:
   lines.append(f'  - `{kind}` at `0x{off:08x}` (delta `{off-t:+#x}`)')
   lines.append(f'    - `{disasm_context(data,off,kind)}`')
  rel=relative_word_refs(data,a,b,t)
  lines.append(f'- signed relative-word candidates `{len(rel)}`')
  for off,bias,disp in rel[:24]:
   lines.append(f'  - word `0x{off:08x}` bias `{bias}` disp `{disp:+#x}` -> target')
  lines.append('')
 return lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);x=ap.parse_args()
 data=x.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED_SHA:raise ValueError(f'unexpected unpacked SHA {sha}')
 lines=['# M11-P relocation-independent PC-relative R2Y xref trace','',f'- exact unpacked SHA-256 `{sha}`','', '## Results','']
 for name in ('leica','driver'):lines+=group(data,name)
 lines += ['## Interpretation boundary','', 'Direct ADR equality is relocation-independent but may still include accidental instruction decodes in mixed code/data regions; coherent clusters and control-flow context are required before promoting a reference to proven consumer code. Relative-word hits are candidate table/offset references only.','']
 x.output.parent.mkdir(parents=True,exist_ok=True);x.output.write_text('\n'.join(lines)+'\n');print(f'wrote {x.output}')
if __name__=='__main__':main()
