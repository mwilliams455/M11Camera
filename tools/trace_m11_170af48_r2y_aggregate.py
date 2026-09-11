#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_OP_REG
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
ENTRY=0x0170AF48
END=0x0170BB1C
DELTA=0x3FAA87D0
KNOWN={
0x0178D0A8:'resource_resolver',0x0172DFC0:'Cat24_YC_wrapper',0x0172EC18:'Cat27_edge_wrapper',0x01731970:'Cat42_CSP_wrapper',
0x01B2D324:'Im_R2Y_Ctrl_Multi_Axis',0x01B624AC:'YC_hw_setter',0x01B68B80:'CSP_hw_setter',0x01B6B388:'Get_RdmaAddr_Multi_Axis_Cntl'}
def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);c.detail=True;c.skipdata=True;return c
def dis(d,a,b):return list(md().disasm(d[a:b],a))
def bl_target(p,w):
 if ((w>>28)&0xf)==0xf or ((w>>25)&7)!=5 or ((w>>24)&1)==0:return None
 x=w&0xffffff
 if x&0x800000:x-=1<<24
 return (p+8+(x<<2))&0xffffffff
def direct_callers(d,t):
 out=[]
 for p in range(0,len(d)-3,4):
  if bl_target(p,u32(d,p))==t:out.append(p)
 return out
def ascii_at(d,p,n=180):
 if not 0<=p<len(d):return None
 o=[]
 for b in d[p:p+n]:
  if b==0:break
  if b in (9,10,13) or 32<=b<127:o.append(chr(b))
  else:return None
 s=''.join(o).strip();return s if len(s)>=5 else None
def movpairs(ins):
 out=[]
 for k,x in enumerate(ins):
  if x.mnemonic!='movw' or '#' not in x.op_str:continue
  r=x.op_str.split(',',1)[0].strip()
  try:lo=int(x.op_str.split('#',1)[1],0)&0xffff
  except:continue
  for y in ins[k+1:k+8]:
   if y.mnemonic=='movt' and y.op_str.startswith(r+',') and '#' in y.op_str:
    try:hi=int(y.op_str.split('#',1)[1],0)&0xffff
    except:break
    out.append((x.address,y.address,r,(hi<<16)|lo));break
 return out
def nearest_pro(d,p,window=0x6000):
 best=None
 for q in range(max(0,p-window)&~3,p+1,4):
  w=u32(d,q)
  if (w&0xffff0000)==0xe92d0000 and (w&(1<<14)):best=q
 return best
def frame_sub(ins):
 rows=[]
 for x in ins[:40]:
  if x.mnemonic=='sub' and len(x.operands)>=3:
   a,b,c=x.operands[:3]
   if a.type==ARM_OP_REG and b.type==ARM_OP_REG and c.type==ARM_OP_IMM:
    if x.reg_name(a.reg)=='sp' and x.reg_name(b.reg)=='sp':rows.append((x.address,int(c.imm)))
 return rows
def local_pointer_calls(ins):
 out=[]
 for i,x in enumerate(ins):
  t=bl_target(x.address,u32(DATA,x.address))
  if t is None:continue
  ctx=ins[max(0,i-14):i+2]
  txt='; '.join(f'{z.address:#x}:{z.mnemonic} {z.op_str}' for z in ctx)
  if 'fp' in txt or 'r11' in txt or 'sp' in txt:out.append((x.address,t,ctx))
 return out
def mem_offsets(ins):
 rows=[]
 for x in ins:
  for op in x.operands:
   if op.type==ARM_OP_MEM:
    base=x.reg_name(op.mem.base) if op.mem.base else ''
    if base in ('fp','r11','sp'):
     rows.append((x.address,x.mnemonic,base,int(op.mem.disp),x.op_str))
 return rows
def main():
 global DATA
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();DATA=a.unpacked.read_bytes();h=hashlib.sha256(DATA).hexdigest()
 if h!=EXPECTED:raise ValueError(h)
 ins=dis(DATA,ENTRY,END)
 calls=[]
 for i,x in enumerate(ins):
  t=bl_target(x.address,u32(DATA,x.address))
  if t is not None:calls.append((x.address,t,KNOWN.get(t,'')))
 L=['# M11-P 0x0170AF48 R2Y aggregate trace','',f'- SHA: `{h}`',f'- function: `0x{ENTRY:08X}..0x{END:08X}`',f'- direct callers: `{[hex(x) for x in direct_callers(DATA,ENTRY)]}`',f'- prologue candidate: `{hex(nearest_pro(DATA,ENTRY) or 0)}`',f'- SP frame subtracts: `{[(hex(p),hex(n)) for p,n in frame_sub(ins)]}`','', '## Direct calls','']
 for p,t,n in calls:L.append(f'- `0x{p:08X}` -> `0x{t:08X}` {n}')
 L += ['','## Relocated strings constructed in function','']
 ss=[]
 for p,q,r,v in movpairs(ins):
  f=(v-DELTA)&0xffffffff;s=ascii_at(DATA,f)
  if s:ss.append((p,q,f,s));L.append(f'- `0x{p:08X}/0x{q:08X}` -> file `0x{f:08X}`: `{s[:160]}`')
 if not ss:L.append('- none')
 L += ['','## Local-pointer call contexts','']
 for p,t,ctx in local_pointer_calls(ins):
  L += [f'### call `0x{p:08X}` -> `0x{t:08X}` {KNOWN.get(t,"")}','```asm']+[f'0x{x.address:08X}: {x.mnemonic} {x.op_str}' for x in ctx]+['```','']
 L += ['## Stack/frame memory-offset inventory','']
 rows=mem_offsets(ins)
 vals=sorted(set((b,o) for _,_,b,o,_ in rows),key=lambda z:(z[0],z[1]))
 L.append(f'- distinct fp/sp offsets: `{[(b,hex(o) if o>=0 else "-"+hex(-o)) for b,o in vals]}`')
 L += ['','## Stores around the exact 3x3 basis aggregate','```asm']
 for x in ins:
  if 0x0170B640<=x.address<=0x0170B980:L.append(f'0x{x.address:08X}: {x.mnemonic} {x.op_str}')
 L += ['```','','## Full tail after aggregate initialization','```asm']
 for x in ins:
  if x.address>=0x0170B980:L.append(f'0x{x.address:08X}: {x.mnemonic} {x.op_str}')
 L += ['```','','## Interpretation boundary','','The exact MCYC/YCC basis is a strong compiler/data fingerprint but not proof of MCC. This function is promoted only if its aggregate is passed into a path that constructs/programs MultiAxis/MCC state or contains an embedded control layout that maps to the closed 0x78C CtrlMultiAxis ABI.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
