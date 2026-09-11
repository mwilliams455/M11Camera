#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

B2R_WRAPPER=0x0170AF48
B2R_CALLER_SITE=0x01755EAC
WB_CALL=0x0170B644
SENS_CALL=0x0170B6BC
HPF_CALL=0x0170BB10

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def bl_target(p,w):
    if ((w>>28)&0xf)==0xf or ((w>>24)&0xf)!=0xb: return None
    x=w&0xffffff
    if x&0x800000: x-=1<<24
    return (p+8+(x<<2))&0xffffffff

def md():
    c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.detail=True; c.skipdata=True; return c

def nearest_prologue(c,d,target,window=0x7000):
    best=None
    for p in range(max(0,target-window)&~3,target+1,4):
        xs=list(c.disasm(d[p:p+4],p,count=1))
        if not xs: continue
        x=xs[0]; s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s): best=p
    return best

def func(c,d,entry,through,max_len=0x9000):
    out=[]; passed=False
    for x in c.disasm(d[entry:min(len(d),entry+max_len)],entry):
        out.append(x)
        if x.address>=through: passed=True
        if passed:
            s=(x.mnemonic+' '+x.op_str).lower()
            if (x.mnemonic=='pop' and 'pc' in x.op_str.lower()) or s.startswith('bx lr') or (x.mnemonic.startswith('ldm') and 'pc' in x.op_str.lower()): break
    return out

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def callers(d,target):
    return [p for p in range(0,len(d)-3,4) if bl_target(p,u32(d,p))==target]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    c=md()
    entry=nearest_prologue(c,d,B2R_CALLER_SITE)
    if entry is None: raise RuntimeError('caller prologue')
    cin=func(c,d,entry,B2R_CALLER_SITE)
    win=list(c.disasm(d[0x0170B5E8:0x0170BB1C],0x0170B5E8))
    head=list(c.disasm(d[B2R_WRAPPER:0x0170B070],B2R_WRAPPER))
    L=['# M11-P B2R photographic control provenance','',f'- SHA: `{h}`',f'- B2R wrapper: `0x{B2R_WRAPPER:08X}`',f'- wrapper callers: `{[hex(x) for x in callers(d,B2R_WRAPPER)]}`',f'- unique known caller function: `0x{entry:08X}` via callsite `0x{B2R_CALLER_SITE:08X}`','']
    L += ['## B2R wrapper argument capture / entry','```asm']+[fmt(x) for x in head]+['```','']
    L += ['## Unique caller context','```asm']
    for x in cin:
        if B2R_CALLER_SITE-0x240 <= x.address <= B2R_CALLER_SITE+0x80: L.append(fmt(x))
    L += ['```','']
    L += ['## Photographic-control construction tail','', 'This span contains the complete local construction for WB gain, sensitivity/adaptive interpolation, and HPF immediately before their pinned Milbeaut setters.','```asm']+[fmt(x) for x in win]+['```','']
    # Inventory source-object reads in wrapper tail so dynamic fields can be distinguished from compiled constants.
    L += ['## Source-config reads in photographic tail','']
    for x in win:
        if x.mnemonic.startswith('ldr') and '[r3, #' in x.op_str:
            L.append(f'- `{fmt(x)}`')
    L += ['','## Decision boundary','','WB/sensitivity/HPF are renderer-relevant only to the extent that they affect pixel formation and are not already represented by RAW metadata + LibRaw/demosaic. Dynamic source-config fields must be traced to their producer before adding them. Compiled HPF/interpolation defaults may justify a separate Bayer-stage reconstruction candidate, but not a change to RENDER1H colour/tone ordering.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
