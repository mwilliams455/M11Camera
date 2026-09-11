#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from collections import Counter,defaultdict
from pathlib import Path
from extract_m11p_forensics import parse_r2y,map_bytes,sha
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
TARGETS={18:'MCYC',32:'boundaries',40:'area_indices',42:'blend_tail',60:'MCL_one_area',90:'MCK_one_area_or_prefix',150:'MCKplusMCL_one_area',720:'MCL_all_12',1080:'MCK_all_12',1800:'MCKplusMCL_all_12',1932:'CtrlMultiAxis_full'}
def i16_summary(raw):
 if len(raw)%2:return None
 vals=struct.unpack('<'+'h'*(len(raw)//2),raw)
 return {'count':len(vals),'min':min(vals) if vals else None,'max':max(vals) if vals else None,'zero':sum(v==0 for v in vals),'head':list(vals[:24]),'tail':list(vals[-24:])}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED:raise ValueError(h)
 base,_,_,descs=parse_r2y(d)
 rows=[]; sizes=Counter()
 for x in descs:
  raw=map_bytes(d,base,x); n=len(raw); sizes[n]+=1
  if n in TARGETS:
   rows.append((x,raw,i16_summary(raw)))
 L=['# M11-P R2YS MCC-shaped payload-size scan','',f'- unpacked SHA-256: `{h}`',f'- descriptors: `{len(descs)}`',f'- target sizes: `{TARGETS}`','', '## Exact-size hits','']
 if not rows:L.append('- none')
 for x,raw,s in rows:
  L += [f'### descriptor `{x["index"]}` — {TARGETS[len(raw)]}',f'- category: `{x["category"]}`',f'- flags: `{x["flags_hex"]}`',f'- map size: `{len(raw)}`',f'- map offset: `0x{x["map_offset_abs"]:08X}`',f'- dependencies: `{x["dependencies_s32"]}`',f'- SHA-256: `{sha(raw)}`']
  if s:L += [f'- i16 count/min/max/zeros: `{s["count"]}/{s["min"]}/{s["max"]}/{s["zero"]}`',f'- i16 head: `{s["head"]}`',f'- i16 tail: `{s["tail"]}`']
  L.append('')
 L += ['## Near-target size distribution','']
 # useful exact natural multiples/nearby structs
 interesting=[]
 for n,c in sorted(sizes.items()):
  if n<=220 or any(abs(n-t)<=16 for t in (720,1080,1800,1932)) or n%90==0 or n%60==0 or n%150==0:interesting.append((n,c))
 L.append(f'`{interesting}`')
 L += ['','## Consecutive descriptor combinations near 1800/1932','']
 # Scan adjacent descriptor map sizes in descriptor order for short runs whose total equals structural totals.
 for i in range(len(descs)):
  tot=0
  for j in range(i,min(len(descs),i+16)):
   raw=map_bytes(d,base,descs[j]);tot+=len(raw)
   if tot in (1800,1932):
    L.append(f'- descriptors `{i}..{j}` total `{tot}`: categories `{[descs[k]["category"] for k in range(i,j+1)]}`, sizes `{[len(map_bytes(d,base,descs[k])) for k in range(i,j+1)]}`')
   if tot>1950:break
 L += ['','## Interpretation boundary','','A size match is only a discovery hint. A candidate becomes MCC evidence only if its payload flows into a MultiAxis object/hardware consumer or its field geometry/values independently match the closed MCC ABI.','']
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
