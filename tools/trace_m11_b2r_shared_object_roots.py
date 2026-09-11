#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

FUNCS={
0x017B8558:-0x8c,
0x017B8990:-0xb4,
0x017B8F4C:-0xb4,
0x017B93A0:-0xcc,
0x017B9BCC:-0xac,
0x017BA2C4:-0xa4,
0x017BA734:-0xa4,
0x017BABA4:-0xa4,
0x017BB014:-0xa4,
}
DELTA=0x3FAA87D0

def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def bl_target(p,w):
    if ((w>>28)&0xf)==0xf or ((w>>24)&0xf)!=0xb:return None
    x=w&0xffffff
    if x&0x800000:x-=1<<24
    return (p+8+(x<<2))&0xffffffff

def one(md,d,p):
    x=list(md.disasm(d[p:p+4],p,count=1));return x[0] if x else None

def next_pro(md,d,p,limit=0x7000):
    for q in range(p+4,min(len(d)-4,p+limit),4):
        x=one(md,d,q)
        if not x:continue
        s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s):return q
    return min(len(d),p+limit)
def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def ascii_at(d,p,n=180):
    if not 0<=p<len(d):return None
    o=[]
    for b in d[p:p+n]:
        if b==0:break
        if b in (9,10,13) or 32<=b<127:o.append(chr(b))
        else:return None
    s=''.join(o).strip();return s if len(s)>=5 else None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11-P B2R shared per-frame object roots','',f'- SHA: `{h}`','']
    for entry,disp in FUNCS.items():
        end=next_pro(md,d,entry)
        ins=list(md.disasm(d[entry:end],entry))
        pat=f'[fp, #-0x{-disp:x}]'
        hits=[i for i,x in enumerate(ins) if pat in x.op_str]
        L += [f'## function `0x{entry:08X}` target slot `{pat}`',f'- span end: `0x{end:08X}`',f'- target-slot references: `{len(hits)}`','']
        # first 80 insns establishes ABI/arguments
        L += ['### entry','```asm']+[fmt(x) for x in ins[:100]]+['```','']
        L += ['### all writes / key reads of target slot','']
        for i in hits:
            x=ins[i]
            is_write=x.mnemonic.startswith('str')
            if is_write or x.mnemonic.startswith('ldr'):
                L += [f'#### `0x{x.address:08X}` {"WRITE" if is_write else "READ"}','```asm']+[fmt(z) for z in ins[max(0,i-14):min(len(ins),i+15)]]+['```','']
        # strings in function for identity
        L += ['### strings','']
        seen=set()
        for i,x in enumerate(ins):
            if x.mnemonic!='movw' or '#' not in x.op_str:continue
            reg=x.op_str.split(',',1)[0].strip()
            try:lo=int(x.op_str.split('#',1)[1],0)&0xffff
            except:continue
            for y in ins[i+1:i+8]:
                if y.mnemonic=='movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
                    try:hi=int(y.op_str.split('#',1)[1],0)&0xffff
                    except:break
                    v=(hi<<16)|lo
                    for off,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                        s=ascii_at(d,off)
                        if s and (off,s) not in seen:
                            seen.add((off,s));L.append(f'- `{label}` `0x{off:08X}`: `{s[:180]}`')
                    break
        L.append('')
    L += ['## Decision boundary','','Promote the shared object as an AWB/IQ frame-state source only if the target local slot is traced to a stable function argument/member with corroborating strings/producer semantics. The +0x1AC/+0x1AE/+0x1B0 fields themselves remain exact B2R R/G/B gain sources regardless.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
