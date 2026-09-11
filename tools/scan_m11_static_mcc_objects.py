#!/usr/bin/env python3
"""Scan exact M11-P 2.6.1 firmware for static CtrlMultiAxis-like MCC objects.

Anchor: Leica Category24 independently recovers the canonical 9x int16 YC basis
[77,150,29,-43,-85,128,128,-107,-21]. Public Milbeaut CtrlMultiAxis begins
with a 9x int16 MCYC basis. This scan asks whether that exact 18-byte basis is
also the start of a full 0x78c-byte object in Leica firmware.

A candidate is ranked only by public field-shape/range constraints; no renderer
change is made and no public/demo coefficients are substituted for Leica data.
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
MCYC=(77,150,29,-43,-85,128,128,-107,-21)
SIG=struct.pack('<9h',*MCYC)
SIZE=0x78C
RELOC_HINT=0x3FAA87D0  # proven for nearby Im_R2Y API rodata strings; hint only

# Natural uint16/int16 packed CtrlMultiAxis offsets.
O_BOUND=0x12; O_INDEX=0x32; O_MCK=0x5A; O_MCL=0x492; O_BLEND=0x762

def u16s(b,off,n): return struct.unpack_from('<'+'H'*n,b,off)
def i16s(b,off,n): return struct.unpack_from('<'+'h'*n,b,off)
def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def mov_imm(w,kind):
 tag=w&0x0FF00000; want=0x03000000 if kind=='movw' else 0x03400000
 if tag!=want: return None
 return ((w>>12)&0xF),((((w>>16)&0xF)<<12)|(w&0xFFF))

def find_all(d,n):
 out=[]; p=0
 while True:
  p=d.find(n,p)
  if p<0:return out
  out.append(p); p+=1

def pointer_refs(d,value):
 raw=find_all(d,struct.pack('<I',value&0xffffffff))
 pairs=[]
 lo=0x01000000; hi=min(0x02000000,len(d))
 low=value&0xffff; high=(value>>16)&0xffff
 for p in range(lo,hi-4,4):
  a=mov_imm(u32(d,p),'movw')
  if a is None or a[1]!=low: continue
  rd=a[0]
  for q in range(p+4,min(p+32,hi),4):
   b=mov_imm(u32(d,q),'movt')
   if b==(rd,high): pairs.append((p,q,rd)); break
 return raw,pairs

def parse_candidate(d,p):
 if p+SIZE>len(d): return None
 b=d[p:p+SIZE]
 if b[:18]!=SIG:return None
 boundaries=u16s(b,O_BOUND,16)
 indices=u16s(b,O_INDEX,20)
 mck=i16s(b,O_MCK,12*45)
 mcl=i16s(b,O_MCL,12*30)
 off=O_BLEND
 cyc_alpha=u16s(b,off,1)[0]; off+=2
 cyc_gain=u16s(b,off,4); off+=8
 cyc_border=u16s(b,off,4); off+=8
 cba_alpha=u16s(b,off,1)[0]; off+=2
 cba_offset=u16s(b,off,4); off+=8
 cba_gain=i16s(b,off,4); off+=8
 cba_border=u16s(b,off,3); off+=6
 assert off==SIZE
 checks={
  'boundary_12bit': all(x<=0xfff for x in boundaries),
  'area_index_0_11': all(x<=11 for x in indices),
  'mck_reasonable': all(-4096<=x<=4095 for x in mck),
  'mcl_reasonable': all(-4096<=x<=4095 for x in mcl),
  'cyc_alpha_6bit': cyc_alpha<=63,
  'cyc_gain_12bit': all(x<=0xfff for x in cyc_gain),
  'cyc_border_12bit': all(x<=0xfff for x in cyc_border),
  'cba_alpha_6bit': cba_alpha<=63,
  'cba_offset_11bit': all(x<=0x7ff for x in cba_offset),
  'cba_gain_signed9': all(-256<=x<=255 for x in cba_gain),
  'cba_border_12bit': all(x<=0xfff for x in cba_border),
 }
 score=sum(checks.values())
 return {'offset':p,'sha':hashlib.sha256(b).hexdigest(),'boundaries':boundaries,'indices':indices,
         'mck':mck,'mcl':mcl,'tail':(cyc_alpha,cyc_gain,cyc_border,cba_alpha,cba_offset,cba_gain,cba_border),
         'checks':checks,'score':score}

def stats(v):
 return {'min':min(v),'max':max(v),'zero':sum(x==0 for x in v),'unity1024':sum(x==1024 for x in v),'neg':sum(x<0 for x in v)}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED_SHA: raise ValueError(h)
 hits=find_all(d,SIG); cand=[parse_candidate(d,p) for p in hits]; cand=[x for x in cand if x]; cand.sort(key=lambda x:(x['score'], -x['offset']),reverse=True)
 lines=['# M11-P static MCC object scan','',f'- unpacked SHA-256: `{h}`',f'- MCYC signature: `{list(MCYC)}`',f'- signature hits: `{len(hits)}`',f'- object size tested: `{SIZE}` (`0x{SIZE:x}`)','',
        '## Ranked candidates','', '| score / 11 | file offset | object SHA-256 | all checks |', '| ---: | --- | --- | --- |']
 for x in cand:
  lines.append(f"| {x['score']} | `0x{x['offset']:08x}` | `{x['sha']}` | {'yes' if x['score']==len(x['checks']) else 'no'} |")
 for rank,x in enumerate(cand[:30],1):
  p=x['offset']; runtime=(p+RELOC_HINT)&0xffffffff; raw,pairs=pointer_refs(d,runtime)
  lines += ['',f'## Candidate {rank} — `0x{p:08x}` score {x["score"]}/11','',
            f'- checks: `{x["checks"]}`',f'- boundaries: `{list(x["boundaries"])}`',f'- area indices: `{list(x["indices"])}`',
            f'- MCK stats: `{stats(x["mck"])}`',f'- MCL stats: `{stats(x["mcl"])}`',
            f'- tail: cycAlpha `{x["tail"][0]}`, cycGain `{list(x["tail"][1])}`, cycBorder `{list(x["tail"][2])}`, cbaAlpha `{x["tail"][3]}`, cbaOffset `{list(x["tail"][4])}`, cbaGain `{list(x["tail"][5])}`, cbaBorder `{list(x["tail"][6])}`',
            f'- rodata-relocation hypothesis runtime pointer: `0x{runtime:08x}`',f'- raw runtime-pointer slots: `{[hex(q) for q in raw[:50]]}`',f'- MOVW/MOVT runtime-pointer constructions: `{[(hex(q),hex(r),"r"+str(reg)) for q,r,reg in pairs[:50]]}`']
  # Emit per-family SHA/stat summaries, not a blind 1.9KB byte dump.
  for i,name in enumerate('ABCDEFGHIJKL'):
   mv=x['mck'][i*45:(i+1)*45]; lv=x['mcl'][i*30:(i+1)*30]
   lines.append(f'- area {name}: MCK `{stats(mv)}` SHA `{hashlib.sha256(struct.pack("<45h",*mv)).hexdigest()}`; MCL `{stats(lv)}` SHA `{hashlib.sha256(struct.pack("<30h",*lv)).hexdigest()}`')
 lines += ['','## Interpretation boundary','',
          'An 18-byte MCYC signature hit is not sufficient. A static MCC object becomes strong evidence only if the full 0x78C field layout passes the independent public range constraints and code/data references support use in the Leica R2Y path. The proven API-string relocation is used only as a pointer-reference hint, not assumed as a universal section mapping.','']
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
