#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R1
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

TARGET=0x017B9BCC
DELTA=0x3FAA87D0

def u32(d,p):return struct.unpack_from('<I',d,p)[0]
def bl_target(p,w):
    if ((w>>28)&0xf)==0xf or ((w>>24)&0xf)!=0xb:return None
    x=w&0xffffff
    if x&0x800000:x-=1<<24
    return (p+8+(x<<2))&0xffffffff

def callers(d,t):return [p for p in range(0,len(d)-3,4) if bl_target(p,u32(d,p))==t]
def one(md,d,p):
    xs=list(md.disasm(d[p:p+4],p,count=1));return xs[0] if xs else None

def pro(md,d,p,w=0x10000):
    best=None
    for q in range(max(0,p-w)&~3,p+1,4):
        x=one(md,d,q)
        if not x:continue
        s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s):best=q
    return best

def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def ascii_at(d,p,n=180):
    if not 0<=p<len(d):return None
    out=[]
    for b in d[p:p+n]:
        if b==0:break
        if b in (9,10,13) or 32<=b<127:out.append(chr(b))
        else:return None
    s=''.join(out).strip();return s if len(s)>=5 else None

def strings(ins,d):
    rows=[];seen=set()
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
                    if s and (off,s) not in seen:seen.add((off,s));rows.append((off,label,s))
                break
    return rows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    cs=callers(d,TARGET)
    L=['# M11-P still B2R/R2Y frame-object parent trace','',f'- SHA: `{h}`',f'- target `img_wfq_job_b2b_r2y_0`: `0x{TARGET:08X}`',f'- direct callers: `{[hex(x) for x in cs]}`','']
    for call in cs:
        e=pro(md,d,call)
        if e is None:e=max(0,call-0x2000)
        ins=list(md.disasm(d[e:call+4],e))
        wr=[]
        for i,x in enumerate(ins):
            if x.address>=call:break
            try:_,writes=x.regs_access()
            except:writes=[]
            if ARM_REG_R1 in writes:wr.append((i,x))
        L += [f'## call `0x{call:08X}` parent `0x{e:08X}`','']
        if wr:
            i,x=wr[-1];L.append(f'- nearest r1 writer: `{fmt(x)}`');L += ['```asm']+[fmt(z) for z in ins[max(0,i-30):min(len(ins),i+25)]]+['```','']
        L += ['### parent entry','```asm']+[fmt(z) for z in ins[:120]]+['```','']
        ss=strings(ins,d)
        if ss:
            L += ['### strings','']+[f'- {lab} `0x{off:08X}`: `{s[:180]}`' for off,lab,s in ss]+['']
    L += ['## Decision boundary','','The frame-state object is promoted to a named IQ/AWB object only if its parent provenance or strings establish that role. Regardless of naming, the Leica still B2R path demonstrably consumes R/G/B gains from the object at +0x1AC/+0x1AE/+0x1B0.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
