#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

ENTRY=0x01755408
END=0x01755EB8
WRAPPER=0x0170AF48
DELTA=0x3FAA87D0

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def bl_target(p,w):
    if ((w>>28)&0xf)==0xf or ((w>>24)&0xf)!=0xb: return None
    x=w&0xffffff
    if x&0x800000: x-=1<<24
    return (p+8+(x<<2))&0xffffffff

def callers(d,t): return [p for p in range(0,len(d)-3,4) if bl_target(p,u32(d,p))==t]
def ascii_at(d,p,n=180):
    if not 0<=p<len(d): return None
    out=[]
    for b in d[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else: return None
    s=''.join(out).strip(); return s if len(s)>=5 else None

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    ins=list(md.disasm(d[ENTRY:END],ENTRY))
    L=['# M11-P B2R WB source provenance', '', f'- SHA: `{h}`',f'- function: `0x{ENTRY:08X}..0x{END:08X}`',f'- direct callers: `{[hex(x) for x in callers(d,ENTRY)]}`','']
    L += ['## Function entry / argument capture','```asm']+[f'0x{x.address:08X}: {x.mnemonic} {x.op_str}' for x in ins[:100]]+['```','']
    L += ['## Direct calls','']
    for x in ins:
        t=bl_target(x.address,u32(d,x.address))
        if t is not None: L.append(f'- `0x{x.address:08X}` -> `0x{t:08X}`' + (' B2R_WRAPPER' if t==WRAPPER else ''))
    L += ['','## Relocated strings','']
    seen=set()
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or '#' not in x.op_str: continue
        reg=x.op_str.split(',',1)[0].strip()
        try: lo=int(x.op_str.split('#',1)[1],0)&0xffff
        except: continue
        for y in ins[i+1:i+8]:
            if y.mnemonic=='movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
                try: hi=int(y.op_str.split('#',1)[1],0)&0xffff
                except: break
                v=(hi<<16)|lo
                for off,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(d,off)
                    if s and (off,s) not in seen:
                        seen.add((off,s)); L.append(f'- `0x{x.address:08X}/0x{y.address:08X}` {label} `0x{off:08X}`: `{s[:160]}`')
                break
    L += ['','## fp-0x28 provenance contexts','']
    hits=[]
    for i,x in enumerate(ins):
        if '[fp, #-0x28]' in x.op_str:
            hits.append(i)
    for i in hits:
        L += [f'### `0x{ins[i].address:08X}`','```asm']+[f'0x{z.address:08X}: {z.mnemonic} {z.op_str}' for z in ins[max(0,i-18):min(len(ins),i+20)]]+['```','']
    L += ['## WB triplet extraction / destination config','```asm']
    for x in ins:
        if 0x01755D20 <= x.address <= 0x01755E20: L.append(f'0x{x.address:08X}: {x.mnemonic} {x.op_str}')
    L += ['```','','## Decision boundary','','The three halfwords at source +0x1AC/+0x1AE/+0x1B0 are promoted as Leica B2R WB gains only after their source object is identified. If the object is sensor/AWB metadata and the values correspond to DNG AsShotNeutral (reciprocal-normalised in Q8), the renderer should avoid applying a second WB transform; if the source contains a separate Leica-domain gain transform, it may require explicit Bayer-domain treatment.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
