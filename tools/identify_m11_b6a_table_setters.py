#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA=0x3FAA87D0
FUNCS=[0x01B6A024,0x01B6A250,0x01B6A480,0x01B6A6AC,0x01B6A8DC,0x01B6AB08,0x01B6AD38]
def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);c.skipdata=True;return c
def dis(d,a,b):return list(md().disasm(d[a:b],a))
def ascii_at(d,p,n=200):
 if not(0<=p<len(d)):return None
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
    out.append((x.address,y.address,(hi<<16)|lo));break
 return out
def fend(d,a,cap=0x1000):
 for i in dis(d,a,min(len(d),a+cap)):
  if i.address>a+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or(i.mnemonic=='bx' and i.op_str.strip()=='lr')):return i.address+4
 return min(len(d),a+cap)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise ValueError(h)
 L=['# M11-P Cat28-40 low-level setter identity','',f'- SHA: `{h}`','']
 for f in FUNCS:
  e=fend(d,f);ins=dis(d,f,e);L += [f'## `0x{f:08X}..0x{e:08X}`','']
  ss=[]
  for x,y,v in movpairs(ins):
   p=(v-DELTA)&0xffffffff;s=ascii_at(d,p)
   if s:ss.append((x,y,v,p,s))
  L.append(f'- relocated strings: `{[(hex(p),s[:120]) for _,_,_,p,s in ss]}`')
  L += ['','```asm']+[f'0x{i.address:08X}: {i.mnemonic} {i.op_str}' for i in ins]+['```','']
 L += ['## Boundary','','Identity requires firmware string and/or concrete register/table-access behavior; no MCC inference from call adjacency.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n')
if __name__=='__main__':main()
