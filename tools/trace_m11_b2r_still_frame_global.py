#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

GLOBAL=0x43433774
DELTA=0x3FAA87D0


def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def one(md,d,p):
    xs=list(md.disasm(d[p:p+4],p,count=1)); return xs[0] if xs else None

def prologue(md,d,p,w=0x12000):
    best=None
    for q in range(max(0,p-w)&~3,p+1,4):
        x=one(md,d,q)
        if not x: continue
        s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s): best=q
    return best

def next_prologue(md,d,p,lim=0x10000):
    for q in range(p+4,min(len(d)-4,p+lim),4):
        x=one(md,d,q)
        if not x: continue
        s=x.op_str.lower()
        if (x.mnemonic=='push' and 'lr' in s) or (x.mnemonic.startswith('stm') and 'sp!' in s and 'lr' in s): return q
    return min(len(d),p+lim)

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def ascii_at(d,p,n=180):
    if not 0 <= p < len(d): return None
    out=[]
    for b in d[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else: return None
    s=''.join(out).strip(); return s if len(s)>=5 else None

def strings(ins,d):
    rows=[]; seen=set()
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
                        seen.add((off,s)); rows.append((off,label,s))
                break
    return rows

def refs(md,d):
    out=[]
    lo=GLOBAL&0xffff; hi=(GLOBAL>>16)&0xffff
    # Exact MOVW/MOVT construction, allowing a short instruction gap.
    for p in range(0,len(d)-32,4):
        x=one(md,d,p)
        if not x or x.mnemonic!='movw' or '#' not in x.op_str: continue
        try: v=int(x.op_str.split('#',1)[1],0)&0xffff
        except: continue
        if v!=lo: continue
        reg=x.op_str.split(',',1)[0].strip()
        for q in range(p+4,min(p+32,len(d)-4),4):
            y=one(md,d,q)
            if not y: continue
            if y.mnemonic=='movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
                try: vh=int(y.op_str.split('#',1)[1],0)&0xffff
                except: break
                if vh==hi:
                    # Capture first use of the constructed address within 8 insns.
                    uses=[]
                    for r in range(q+4,min(q+36,len(d)-4),4):
                        z=one(md,d,r)
                        if z and reg in z.op_str: uses.append(z)
                    out.append((p,q,reg,uses))
                break
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    rr=refs(md,d)
    L=['# M11-P still B2R frame-state global provenance','',f'- SHA: `{h}`',f'- global slot: `0x{GLOBAL:08X}`',f'- exact MOVW/MOVT references: `{len(rr)}`','']
    grouped={}
    for p,q,reg,uses in rr:
        e=prologue(md,d,p)
        if e is None: e=max(0,p-0x400)
        grouped.setdefault(e,[]).append((p,q,reg,uses))
    for e,items in sorted(grouped.items()):
        end=next_prologue(md,d,e)
        ins=list(md.disasm(d[e:end],e))
        L += [f'## function `0x{e:08X}`',f'- span end: `0x{end:08X}`',f'- references: `{len(items)}`','']
        for p,q,reg,uses in items:
            idx=next((i for i,x in enumerate(ins) if x.address==p),0)
            L += [f'### reference `0x{p:08X}` via `{reg}`','```asm']+[fmt(z) for z in ins[max(0,idx-18):min(len(ins),idx+34)]]+['```','']
            if uses:
                L += ['first uses:']+[f'- `{fmt(z)}`' for z in uses[:8]]+['']
        ss=strings(ins,d)
        if ss:
            L += ['### strings','']+[f'- {lab} `0x{off:08X}`: `{s[:180]}`' for off,lab,s in ss]+['']
    L += ['## Decision boundary','',
          'A producer is accepted for the B2R R/G/B triplet only if this global pointer can be followed to an object write/copy path that reaches +0x1AC/+0x1AE/+0x1B0, or to a named AWB/IQ producer with equivalent direct evidence. Mere access to the global slot is not enough.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
