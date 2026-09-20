#!/usr/bin/env python3
"""Read-only canonical-firmware still-IQ call graph and bounded byte export.
External calls remain open boundaries. No claim of MCC inactivity or identity.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
EXPECTED = '28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA = 0x3FAA87D0
ROOT = 0x01732750
LO, HI = 0x0172C19C, 0x01732A64
MCC, GETTER = 0x01B2D324, 0x01B6B388
CODE_LO, CODE_HI = 0x01600000, 0x01C90000
RANGES = {
 'still_iq': (LO, HI),
 'still_job': (0x0176E6F8, 0x0177045C),
 'parameter_selector': (0x0178A800, 0x0178E800),
 'r2y_reset_manager': (0x01B18000, 0x01B1B9C8),
 'r2y_init_common': (0x01B1B9C8, 0x01B1E3EC),
 'mcc_writer': (MCC, 0x01B60320),
 'rdma_helpers': (0x01B6B000, 0x01B6B800),
}
def u32(data: bytes, at: int) -> int:
 return struct.unpack_from('<I', data, at)[0]
def branch(at: int, word: int) -> dict | None:
 """A32 B/BL/BLX-immediate, with explicit destination instruction state."""
 if word & 0x0E000000 != 0x0A000000: return None
 imm = word & 0xFFFFFF
 if imm & 0x800000: imm -= 1 << 24
 cond = word >> 28
 if cond == 15:
  return {'at':at,'word':word,'kind':'BLX','target':(at+8+(imm<<2)+((word>>23)&2))&0xFFFFFFFF,'state':'Thumb','conditional':False}
 return {'at':at,'word':word,'kind':'BL' if word&(1<<24) else 'B','target':(at+8+(imm<<2))&0xFFFFFFFF,'state':'A32','conditional':cond!=14}
def cstring(data: bytes, at: int) -> str | None:
 if not 0 <= at < len(data): return None
 end = data.find(b'\0', at, min(len(data), at+512))
 if end < at+4: return None
 b = data[at:end]
 return b.decode('ascii') if all(32<=x<127 or x in (9,10,13) for x in b) else None
def pair_value(w: int, t: int) -> int | None:
 if w&0x0FF00000!=0x03000000 or t&0x0FF00000!=0x03400000: return None
 if (w>>12)&15!=(t>>12)&15 or w>>28!=t>>28 or w>>28==15: return None
 return (((w>>4)&0xF000)|(w&0xFFF)|((((t>>4)&0xF000)|(t&0xFFF))<<16))
def root_graph(data: bytes, root: int = ROOT, lo: int = LO, hi: int = HI) -> dict:
 """Conservative CFG: unresolved PC writes stop traversal, not fall through.
 Calls within named IQ range are followed; external calls remain boundaries.
 """
 import capstone as cs
 from capstone.arm import ARM_REG_PC
 md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_ARM|cs.CS_MODE_LITTLE_ENDIAN); md.detail=True
 pending_functions=[root]; functions={}
 while pending_functions:
  entry=pending_functions.pop()
  if entry in functions: continue
  pending=[entry]; seen=set(); calls=[]; tails=[]; unresolved=[]; returns=[]; stores=[]
  while pending:
   at=pending.pop()
   if at in seen: continue
   if not lo<=at<hi:
    unresolved.append({'at':at,'reason':'outside IQ range'}); continue
   seen.add(at)
   ins=next(md.disasm(data[at:at+4],at,count=1),None)
   if ins is None or ins.size!=4:
    unresolved.append({'at':at,'reason':'undecodable A32 word'}); continue
   b=branch(at,u32(data,at))
   if b:
    if b['kind'] in ('BL','BLX'):
     calls.append(b)
     if b['state']=='A32' and lo<=b['target']<hi: pending_functions.append(b['target'])
     pending.append(at+4)
    else:
     if lo<=b['target']<hi: pending.append(b['target'])
     else: tails.append(b)
     if b['conditional']: pending.append(at+4)
    continue
   if u32(data,at)==0xE12FFF1E or (ins.mnemonic.startswith('pop') and any(o.type==cs.arm.ARM_OP_REG and o.reg==ARM_REG_PC for o in ins.operands)):
    returns.append(at)
    if u32(data,at)>>28!=14: pending.append(at+4)
    continue
   if ins.mnemonic.startswith(('str','stm','vstr','vstm')):
    stores.append({'at':at,'text':ins.mnemonic+' '+ins.op_str})
   try: _,written=ins.regs_access()
   except cs.CsError:
    unresolved.append({'at':at,'reason':'register-access analysis failed'}); continue
   if ins.mnemonic.startswith(('bx','blx')) or ARM_REG_PC in written:
    unresolved.append({'at':at,'reason':'unresolved control transfer','text':ins.mnemonic+' '+ins.op_str}); continue
   pending.append(at+4)
  functions[entry]={'entry':entry,'visited':sorted(seen),'calls':calls,'tail_branches':tails,'returns':returns,'unresolved':unresolved,'stores':stores}
 return {'root':root,'bounds':[lo,hi],'functions':list(functions.values()),'qualification':'external calls are boundaries; no claim of MCC inactivity or identity'}
def main() -> None:
 ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('unpacked',type=Path); ap.add_argument('--output-dir',type=Path,required=True); args=ap.parse_args()
 data=args.unpacked.read_bytes(); sha=hashlib.sha256(data).hexdigest()
 if sha!=EXPECTED: raise ValueError('noncanonical firmware: '+sha)
 if data[ROOT:ROOT+12].hex()!='08d04de200482de904b08de2': raise ValueError('root prologue mismatch')
 if data[0x01732A60:0x01732A64].hex()!='1eff2fe1': raise ValueError('root return mismatch')
 import capstone as cs
 md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_ARM|cs.CS_MODE_LITTLE_ENDIAN); md.skipdata=True
 out=args.output_dir; out.mkdir(parents=True,exist_ok=True)
 manifest={'firmware_sha256':sha,'ranges':{}}; strings=[]
 for name,(lo,hi) in RANGES.items():
  raw=data[lo:hi]; (out/(name+'.bin')).write_bytes(raw)
  (out/(name+'.asm')).write_text('\n'.join(f'{i.address:08X}: {i.bytes.hex()}  {i.mnemonic:10s} {i.op_str}' for i in md.disasm(raw,lo))+'\n')
  manifest['ranges'][name]={'start':lo,'end_exclusive':hi,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
  for at in range(lo,hi-4,4):
   runtime=pair_value(u32(data,at),u32(data,at+4))
   if runtime is not None:
    static=(runtime-DELTA)&0xFFFFFFFF; text=cstring(data,static)
    if text: strings.append({'at':at,'runtime':runtime,'static':static,'text':text})
 graph=root_graph(data); (out/'graph.json')).write_text(json.dumps(graph,indent=2)+'\n')
 for label,entry,low,high in [('selector',0x178D0A8,0x178A800,0x178D0D8),('init',0x1B1B9C8,0x1B18000,0x1B1BB1C)]:
  (out/(label+'_graph.json')).write_text(json.dumps(root_graph(data,entry,low,high),indent=2)+'\n')
 targets={ROOT,0x01732754,0x0172C19C,0x0178D0A8,MCC,GETTER,0x01B1833C,0x01B18404,0x01B1B9C8,0x01B1CDA4}
 targets|={c['target'] for f in graph['functions'] for c in f['calls']}
 refs=[]
 for at in range(CODE_LO,CODE_HI,4):
  b=branch(at,u32(data,at))
  if b and b['target'] in targets: refs.append(b)
 (out/'target_branch_candidates.json').write_text(json.dumps(refs,indent=2)+'\n')
 (out/'strings.json').write_text(json.dumps(strings,indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 unresolved=[x for f in graph['functions'] for x in f['unresolved']]
 endpoints=Counter(c['target'] for f in graph['functions'] for c in f['calls'] if not LO<=c['target']<HI)
 rows=['# M11 STILLPATH1A - bounded canonical-firmware trace','','Firmware SHA-256: `'+sha+'`','',f'Root: `0x{ROOT:08X}`. Reachable local routines: {len(graph["functions"])}.',f'Unresolved intra-routine transfers: {len(unresolved)}.','','External calls remain open boundaries; this result does not establish MCC inactivity.','','## External direct-call boundaries','']
 rows += [f'- `0x{target:08X}`: {count} reachable call site(s)' for target,count in sorted(endpoints.items())]
 rows += ['','## Unresolved transfers','','```json',json.dumps(unresolved,indent=2),'```','','## Branch scan scope','',f'Aligned A32 candidates only in `[0x{CODE_LO:08X},0x{CODE_HI:08X})`.','BLX-immediate retains Thumb state; raw candidate hits are not automatically executable.','No code-pointer relocation assumption is made by this scan.']
 (out/'stillpath1a.md').write_text('\n'.join(rows)+'\n'); print('\n'.join(rows))
if __name__=='__main__': main()
