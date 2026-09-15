#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,re,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_REG
EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA=0x3FAA87D0
RANGES=[
 ('aaa_dispatch',0x016CED80,0x016CF180),
 ('cm_entry_and_copy',0x016EB010,0x016EC0C0),
 ('colorspec_core',0x016F2108,0x016F27B0),
]
CALLEES=[0x016ED060,0x016ECBEC,0x016ED544,0x016EE62C,0x016F1FB4,0x016F1CB8,0x016F0998,0x016ED8E0,0x016EDA24]

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def dec_mov(w,kind):
    tag=w&0x0ff00000; want=0x03000000 if kind=='w' else 0x03400000
    if tag!=want:return None
    return (w>>12)&15,(((w>>4)&0xf000)|(w&0xfff))
def asc(d,a,n=220):
    if a is None or not(0<=a<len(d)):return None
    b=d[a:a+n];m=re.match(rb'[\x20-\x7e]{4,}\x00',b)
    return m.group()[:-1].decode('ascii','replace') if m else None
def mapped_str(d,v):
    for a in (v,(v-DELTA)&0xffffffff):
        s=asc(d,a)
        if s:return a,s
    return None
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def annotate_range(md,d,lo,hi):
    ins=list(md.disasm(d[lo:hi],lo)); out=[]
    pending={}
    for i in ins:
        note=''
        w=u32(d,i.address)
        mw=dec_mov(w,'w') if w is not None else None
        mt=dec_mov(w,'t') if w is not None else None
        if mw: pending[mw[0]]=(mw[1],i.address)
        elif mt and mt[0] in pending:
            lo16,wa=pending[mt[0]];v=(mt[1]<<16)|lo16
            s=mapped_str(d,v)
            if s: note=f'    ; ptr=0x{v:08X} -> file 0x{s[0]:08X} "{s[1]}"'
        out.append(fmt(i)+note)
    return out

def nearest_push(d,a,window=0x4000):
    for p in range(a&~3,max(0,(a&~3)-window),-4):
        w=u32(d,p)
        if w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14)):return p
    return max(0,a-0x400)
def callers(d,t,lo=0x01500000,hi=0x01b50000):
    out=[]
    for a in range(lo,hi,4):
        w=u32(d,a)
        if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:continue
        imm=w&0xffffff
        if imm&0x800000:imm-=1<<24
        dst=(a+8+(imm<<2))&0xffffffff
        if dst==t:out.append(a)
    return out

def strings(d,lo,hi):
    for m in re.finditer(rb'[\x20-\x7e]{4,}\x00',d[lo:hi]):
        yield lo+m.start(),m.group()[:-1].decode('ascii','replace')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    L=['# M11 ColorSpec -> CC0/CC1 dependency trace','',f'- SHA256 `{h}`',f'- runtime/file string delta assumed/verified by known CM strings: `0x{DELTA:08X}`','']
    L += ['## AAA/CM event strings around 0x02778600','']
    for p,s in strings(d,0x02778400,0x02778B80):L.append(f'- `0x{p:08X}` runtime `0x{p+DELTA:08X}` — `{s}`')
    L += ['','## Color-management strings','']
    for p,s in strings(d,0x0277B600,0x0277BE40):L.append(f'- `0x{p:08X}` runtime `0x{p+DELTA:08X}` — `{s}`')
    for name,lo,hi in RANGES:
        L += ['',f'## Annotated {name} `0x{lo:08X}..0x{hi:08X}`','```asm']+annotate_range(md,d,lo,hi)+['```']
    for t in CALLEES:
        fs=nearest_push(d,t);cs=callers(d,t)
        L += ['',f'## Callee `0x{t:08X}` nearest start `0x{fs:08X}` callers `{[hex(x) for x in cs]}`','```asm']
        L += annotate_range(md,d,t,min(len(d),t+0x280))+['```']
    # enumerate stores into original ColorSpec object in core, retaining a small provenance window
    L += ['','## Writes to live ColorSpec root within 0x016F2108','']
    ins=list(md.disasm(d[0x016F2108:0x016F27B0],0x016F2108))
    for idx,i in enumerate(ins):
        if i.mnemonic.startswith('str'):
            window=' | '.join(fmt(x) for x in ins[max(0,idx-3):idx+1])
            if '#-0x330' in window or '[r3' in i.op_str or '[r2' in i.op_str:
                L.append(f'- `{window}`')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
