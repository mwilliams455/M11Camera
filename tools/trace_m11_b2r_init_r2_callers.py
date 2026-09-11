#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R2
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

TARGET=0x01755408
DELTA=0x3FAA87D0

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def bl_target(p,w):
    if ((w>>28)&0xf)==0xf or ((w>>24)&0xf)!=0xb: return None
    x=w&0xffffff
    if x&0x800000:x-=1<<24
    return (p+8+(x<<2))&0xffffffff

def callers(d,t): return [p for p in range(0,len(d)-3,4) if bl_target(p,u32(d,p))==t]
def one(md,d,p):
    x=list(md.disasm(d[p:p+4],p,count=1)); return x[0] if x else None

def nearest_prologue(md,d,p,window=0x7000):
    best=None
    for q in range(max(0,p-window)&~3,p+1,4):
        x=one(md,d,q)
        if not x: continue
        s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s): best=q
    return best

def ascii_at(d,p,n=180):
    if not 0<=p<len(d): return None
    out=[]
    for b in d[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else:return None
    s=''.join(out).strip(); return s if len(s)>=5 else None

def movpairs(ins):
    rows=[]
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or '#' not in x.op_str:continue
        r=x.op_str.split(',',1)[0].strip()
        try:lo=int(x.op_str.split('#',1)[1],0)&0xffff
        except:continue
        for y in ins[i+1:i+8]:
            if y.mnemonic=='movt' and y.op_str.startswith(r+',') and '#' in y.op_str:
                try:hi=int(y.op_str.split('#',1)[1],0)&0xffff
                except:break
                rows.append((x.address,y.address,(hi<<16)|lo));break
    return rows

def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    cs=callers(d,TARGET)
    L=['# M11-P B2R init r2 caller provenance','',f'- SHA: `{h}`',f'- target: `0x{TARGET:08X}`',f'- direct callers: `{[hex(x) for x in cs]}`','']
    for call in cs:
        entry=nearest_prologue(md,d,call)
        if entry is None:entry=max(0,call-0x1000)
        ins=list(md.disasm(d[entry:call+4],entry))
        writers=[]
        for i,x in enumerate(ins):
            if x.address>=call:break
            try:_,wr=x.regs_access()
            except:wr=[]
            if ARM_REG_R2 in wr:writers.append((i,x))
        L += [f'## call `0x{call:08X}` function `0x{entry:08X}`','']
        if writers:
            idx,x=writers[-1]
            L.append(f'- nearest r2 writer: `{fmt(x)}`')
            L += ['```asm']+[fmt(z) for z in ins[max(0,idx-24):min(len(ins),idx+22)]]+['```']
        else:L.append('- no r2 writer found')
        # include tail before call regardless, for alias/provenance around register copies
        L += ['','### final caller tail','```asm']+[fmt(z) for z in ins[-90:]]+['```','']
        ss=[]
        for p,q,v in movpairs(ins):
            for off,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                s=ascii_at(d,off)
                if s:ss.append((p,q,off,label,s))
        if ss:
            L += ['### strings','']
            seen=set()
            for p,q,off,label,s in ss:
                k=(off,s)
                if k in seen:continue
                seen.add(k);L.append(f'- `0x{p:08X}/0x{q:08X}` {label} `0x{off:08X}`: `{s[:160]}`')
            L.append('')
    L += ['## Decision boundary','','The B2R WB source object is identified only when r2 provenance converges to a named/structured per-shot IQ/AWB object or a stable producer. Similar-looking offsets alone are not enough.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
