#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
STRDELTA=0x3FAA87D0
TARGET_FILE=0x030D1574
TARGET_RUNTIME=(TARGET_FILE+STRDELTA)&0xffffffff

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.skipdata=True; return c
def dis(d,lo,hi): return list(md().disasm(d[lo:hi],lo))
def branch_target(p,w):
 if ((w>>25)&7)!=5 or ((w>>28)&0xF)==0xF: return None
 imm=w&0xffffff
 if imm&0x800000: imm-=1<<24
 return (p+8+(imm<<2))&0xffffffff

def mov_pairs(d,lo,hi,want=None):
 ins=dis(d,lo,hi); out=[]
 for i,x in enumerate(ins):
  if x.mnemonic!='movw' or '#' not in x.op_str: continue
  reg=x.op_str.split(',',1)[0].strip()
  try: low=int(x.op_str.split('#',1)[1],0)&0xffff
  except: continue
  for y in ins[i+1:i+8]:
   if y.mnemonic=='movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
    try: high=int(y.op_str.split('#',1)[1],0)&0xffff
    except: break
    v=(high<<16)|low
    if want is None or v==want: out.append((x.address,y.address,reg,v))
    break
 return out

def is_pro(i):
 s=f'{i.mnemonic} {i.op_str}'.lower(); return (i.mnemonic in ('push','stmdb') and 'sp' in s and 'lr' in s)
def is_ret(i):
 s=f'{i.mnemonic} {i.op_str}'.lower(); return (i.mnemonic=='bx' and i.op_str.strip()=='lr') or (i.mnemonic in ('pop','ldmia') and 'pc' in s)
def bounds(d,a):
 ins=dis(d,max(0,a-0x4000),min(len(d),a+0x8000)); ps=[i.address for i in ins if i.address<=a and is_pro(i)]
 st=max(ps) if ps else max(0,a-0x1000); es=[i.address+4 for i in ins if i.address>a and is_ret(i)]
 return st,(min(es) if es else min(len(d),a+0x3000))
def ascii_at(d,p,limit=180):
 if not (0<=p<len(d)): return None
 b=[]
 for x in d[p:p+limit]:
  if x==0: break
  if x in (9,10,13) or 32<=x<127: b.append(chr(x))
  else: return None
 s=''.join(b).strip(); return s if len(s)>=5 else None

def callers(d,target):
 out=[]
 for p in range(0,len(d)-4,4):
  w=u32(d,p)
  if branch_target(p,w)==target: out.append((p,'BL' if ((w>>24)&1) else 'B'))
 return out

def rawrefs(d,v):
 n=struct.pack('<I',v); out=[]; p=0
 while True:
  p=d.find(n,p)
  if p<0: break
  out.append(p); p+=1
 return out

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED: raise ValueError(h)
 hits=mov_pairs(d,0,len(d),TARGET_RUNTIME)
 lines=['# M11-P MCC RDMA multi-axis entry trace','',f'- unpacked SHA-256: `{h}`',f'- target firmware string file offset: `0x{TARGET_FILE:08X}`',f'- relocated runtime pointer: `0x{TARGET_RUNTIME:08X}`',f'- MOVW/MOVT string-pointer constructions: `{[(hex(x),hex(y),r) for x,y,r,_ in hits]}`','']
 seen=set()
 for x,y,reg,v in hits:
  st,en=bounds(d,x)
  if st in seen: continue
  seen.add(st)
  lines += [f'## Candidate function `0x{st:08X}..0x{en:08X}`',f'- anchor construction at `0x{x:08X}/0x{y:08X}`',f'- direct whole-image callers: `{[(hex(p),k) for p,k in callers(d,st)]}`',f'- raw little-endian function-pointer refs: `{[hex(p) for p in rawrefs(d,st)]}`','', '```asm']
  for i in dis(d,st,en): lines.append(f'0x{i.address:08X}: {i.mnemonic} {i.op_str}')
  lines += ['```','', '### Calls from candidate','']
  c=[]
  for i in dis(d,st,en):
   t=branch_target(i.address,u32(d,i.address))
   if t is not None and ((u32(d,i.address)>>24)&1) and t not in c: c.append(t)
  lines.append(f'- unique BL targets: `{[hex(t) for t in c]}`')
  lines += ['', '### Relocated string constructions in/near candidate','']
  for a0,a1,r,vv in mov_pairs(d,max(0,st-0x100),min(len(d),en+0x100)):
   f=(vv-STRDELTA)&0xffffffff; s=ascii_at(d,f)
   if s: lines.append(f'- `0x{a0:08X}/0x{a1:08X}` -> file `0x{f:08X}`: `{s[:150]}`')
  lines.append('')
 lines += ['## String-table neighborhood','']
 p=max(0,TARGET_FILE-0x500); stop=min(len(d),TARGET_FILE+0x700)
 while p<stop:
  s=ascii_at(d,p)
  if s:
   lines.append(f'- `0x{p:08X}` runtime `0x{(p+STRDELTA)&0xffffffff:08X}`: `{s[:180]}`'); p+=len(s.encode(errors='ignore'))+1
  else: p+=1
 lines += ['', '## Interpretation boundary','', 'This trace is intended to identify Leica\'s RDMA-side multi-axis entry and its caller/descriptor path. It does not by itself establish coefficient values or justify renderer changes.','']
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
