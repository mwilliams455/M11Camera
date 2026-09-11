#!/usr/bin/env python3
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
SETTERS=[0x01B63050,0x01B631B0,0x01B640FC,0x01B65048,0x01B6622C,0x01B66530,0x01B668D4,0x01B67030,0x01B672F0,0x01B67A84]

def md():
 c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.detail=True; c.skipdata=True; return c

def dis(d,a,b): return list(md().disasm(d[a:b],a))
def endfn(d,e,cap=0x2000):
 for i in dis(d,e,min(len(d),e+cap)):
  if i.address>e+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or (i.mnemonic=='bx' and i.op_str.strip()=='lr')): return i.address+4
 return min(len(d),e+cap)
def fmt(i): return f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'

def interesting(i):
 # Keep absolute-address construction, sizeable adds/subs, and large register displacements.
 if i.mnemonic in ('movw','movt'): return True
 for op in i.operands:
  if op.type==ARM_OP_IMM and abs(int(op.imm))>=0x80: return True
  if op.type==ARM_OP_MEM and abs(int(op.mem.disp))>=0x80: return True
 return False

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED: raise ValueError(h)
 lines=['# M11-P default R2Y setter block fingerprints','',f'- SHA: `{h}`','']
 for s in SETTERS:
  e=endfn(d,s); ins=dis(d,s,e); anchors=[i for i in ins if interesting(i)]
  lines += [f'## setter `0x{s:08x}..0x{e:08x}`','',f'- instructions: `{len(ins)}`',f'- anchor lines: `{len(anchors)}`','','```asm']
  lines += [fmt(i) for i in anchors]
  lines += ['```','','### entry excerpt','','```asm']+[fmt(i) for i in ins[:80]]+['```','']
  lines += ['### exit excerpt','','```asm']+[fmt(i) for i in ins[-60:]]+['```','']
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
