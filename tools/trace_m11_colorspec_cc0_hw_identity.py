#!/usr/bin/env python3
from __future__ import annotations
import argparse,bisect,hashlib,struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM,ARM_OP_MEM
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000;END=0x02000000
GET_FRAME=0x01721858;CM_FINISH=0x016EB09C
R2Y_CTRL=0x01B1CDA4;R2Y_BUILDER=0x0172C19C;R2Y_MCC_WRITER=0x01B2D324
FIELDS={0x1F8:'dynamic_CC0',0x250:'DNG_CM1',0x278:'DNG_CM2',0x2A0:'CM_aux48'}
SPECIAL={GET_FRAME,CM_FINISH,R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER}
def u32(d,a):return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b):s=1<<(b-1);return (v^s)-s
def blt(a,w):
 if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
 return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def push(w):return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def imms(i):
 if i.id==0:return []
 out=[]
 for o in i.operands:
  if o.type==ARM_OP_IMM:out.append(o.imm&0xffffffff)
  elif o.type==ARM_OP_MEM:out.append(o.mem.disp&0xffffffff)
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise SystemExit(h)
 pushes=[p for p in range(START,END,4) if push(u32(d,p))]
 def fs(x):
  j=bisect.bisect_right(pushes,x)-1;return pushes[j] if j>=0 else x&~3
 def fe(x):
  j=bisect.bisect_right(pushes,x);return pushes[j] if j<len(pushes) else min(END,x+0x4000)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
 hits=defaultdict(list);special_calls=defaultdict(list);getter_calls=[];cm_calls=[]
 for i in md.disasm(d[START:END],START):
  vals=imms(i)
  for off in FIELDS:
   if off in vals:hits[off].append(i.address)
  t=blt(i.address,u32(d,i.address))
  if t in SPECIAL:
   special_calls[fs(i.address)].append((i.address,t))
   if t==GET_FRAME:getter_calls.append(i.address)
   if t==CM_FINISH:cm_calls.append(i.address)
 getter_funcs=set(fs(x) for x in getter_calls)
 hit_funcs=set(fs(x) for xs in hits.values() for x in xs)
 direct_callers=defaultdict(list);cared=hit_funcs|getter_funcs|{R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER,CM_FINISH}
 for p in range(START,END,4):
  t=blt(p,u32(d,p))
  if t in cared:direct_callers[t].append(p)
 def context(addr,before=0x30,after=0x48):
  lo=max(START,(addr-before)&~3);hi=min(END,(addr+after+3)&~3)
  return [fmt(x) for x in md.disasm(d[lo:hi],lo)]
 def function_touches(f):
  out=[]
  for i in md.disasm(d[f:fe(f)],f):
   vals=imms(i)
   for off,name in FIELDS.items():
    if off in vals and name not in out:out.append(name)
  return out
 L=['# M11 dynamic ColorSpec CC0 -> hardware identity trace','',f'- SHA256 `{h}`','- Exact producer map: `frame+0x1F8 <- ColorSpec root+0x28` (44-byte dynamic CC0), `frame+0x250 <- calibration+0x40` (CM1), `frame+0x278 <- calibration+0x70` (CM2), `frame+0x2A0 <- root+0x82` (48-byte auxiliary block).','']
 L += ['## Producer caller',f'- `0x{CM_FINISH:08X}` calls: `{[hex(x) for x in cm_calls]}`','']
 L += ['## GET_FRAME users',f'- calls `{len(getter_calls)}`; funcs `{[hex(x) for x in sorted(getter_funcs)]}`','']
 for off,name in FIELDS.items():
  L += [f'## +0x{off:X} {name}',f'- instruction hits `{len(hits[off])}`','']
  for x in hits[off]:
   f=fs(x);sp=special_calls.get(f,[])
   L += [f'### `0x{x:08X}` func `0x{f:08X}` GET_FRAME={f in getter_funcs} special=`{[(hex(c),hex(t)) for c,t in sp]}` callers=`{[hex(c) for c in direct_callers.get(f,[])]}`','```asm']+context(x)+['```','']
 L += ['## Intersection: GET_FRAME functions touching CM fields','']
 for f in sorted(getter_funcs & hit_funcs):L.append(f'- `0x{f:08X}` touches `{function_touches(f)}` special `{[(hex(c),hex(t)) for c,t in special_calls.get(f,[])]}` callers `{[hex(c) for c in direct_callers.get(f,[])]}`')
 L += ['','## Known R2Y direct callers','']
 for t in (R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER):L.append(f'- `0x{t:08X}` callers `{[hex(c) for c in direct_callers.get(t,[])]}`')
 for f,cs in sorted(special_calls.items()):
  if any(t in (R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER) for _,t in cs):
   L += ['',f'## R2Y-containing function `0x{f:08X}` fields `{function_touches(f)}`','```asm']
   for ca,t in cs:
    if t in (R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER):L += context(ca,0x60,0x40)
   L += ['```']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
