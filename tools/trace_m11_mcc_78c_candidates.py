#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
ANCHORS=[0x01661D70,0x016655BC]
STRDELTA=0x3FAA87D0

def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def md():
    c=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.skipdata=True; return c

def dis(d,lo,hi): return list(md().disasm(d[lo:hi],lo))
def branch_target(p,w):
    if ((w>>25)&7)!=5 or ((w>>28)&0xF)==0xF: return None
    imm=w&0xffffff
    if imm&0x800000: imm-=1<<24
    return (p+8+(imm<<2))&0xffffffff

def looks_prologue(i):
    s=f'{i.mnemonic} {i.op_str}'.lower()
    return (i.mnemonic in ('push','stmdb') and 'sp' in s and 'lr' in s)
def looks_return(i):
    s=f'{i.mnemonic} {i.op_str}'.lower()
    return (i.mnemonic=='bx' and i.op_str.strip()=='lr') or (i.mnemonic in ('pop','ldmia') and 'pc' in s)

def nearest_bounds(d,a):
    ins=dis(d,max(0,a-0x5000),min(len(d),a+0x9000))
    starts=[i.address for i in ins if i.address<=a and looks_prologue(i)]
    start=max(starts) if starts else max(0,a-0x1000)
    ends=[i.address+4 for i in ins if i.address>a and looks_return(i)]
    end=min(ends) if ends else min(len(d),a+0x3000)
    return start,end

def read_ascii(d,p,limit=160):
    if not (0<=p<len(d)): return None
    out=[]
    for b in d[p:p+limit]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else: return None
    s=''.join(out).strip()
    return s if len(s)>=5 else None

def runtime_strings_in_window(d,lo,hi):
    ins=dis(d,lo,hi); out=[]
    for idx,x in enumerate(ins):
        if x.mnemonic!='movw' or '#' not in x.op_str: continue
        reg=x.op_str.split(',',1)[0].strip()
        try: low=int(x.op_str.split('#',1)[1],0)&0xffff
        except: continue
        for y in ins[idx+1:idx+8]:
            if y.mnemonic=='movt' and y.op_str.startswith(reg+',') and '#' in y.op_str:
                try: high=int(y.op_str.split('#',1)[1],0)&0xffff
                except: break
                v=(high<<16)|low
                f=(v-STRDELTA)&0xffffffff
                s=read_ascii(d,f)
                if s: out.append((x.address,y.address,v,f,s))
                break
    return out

def callers(d,target):
    out=[]
    for p in range(0,len(d)-4,4):
        w=u32(d,p); t=branch_target(p,w)
        if t==target: out.append((p,'BL' if ((w>>24)&1) else 'B'))
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise ValueError(h)
    lines=['# M11-P MCC 0x78C candidate trace','',f'- unpacked SHA-256: `{h}`','- 0x78C = 1932 bytes = closed CtrlMultiAxis object size','']
    bounds=[]
    for anchor in ANCHORS:
        st,en=nearest_bounds(d,anchor); bounds.append((st,en))
        lines += [f'## Anchor `0x{anchor:08X}`',f'- nearest prologue: `0x{st:08X}`',f'- nearest return: `0x{en:08X}`',f'- span: `0x{en-st:X}` bytes',f'- whole-image direct callers to candidate start: `{[(hex(p),k) for p,k in callers(d,st)]}`','', '### Anchor context','```asm']
        for i in dis(d,anchor-0x140,anchor+0x180):
            mark='  ; << 0x78C anchor' if i.address==anchor else ''
            lines.append(f'0x{i.address:08X}: {i.mnemonic} {i.op_str}{mark}')
        lines += ['```','', '### Candidate direct calls','']
        cins=dis(d,st,en)
        seen=[]
        for i in cins:
            w=u32(d,i.address); t=branch_target(i.address,w)
            if t is not None and ((w>>24)&1):
                if t not in seen: seen.append(t)
        lines.append(f'- unique BL targets: `{[hex(x) for x in seen]}`')
        for t in seen[:80]:
            ss=runtime_strings_in_window(d,t,min(len(d),t+0x300))
            if ss:
                lines.append(f'  - `0x{t:08X}` strings: `{[(hex(f),s[:90]) for _,_,_,f,s in ss[:6]]}`')
        lines += ['', '### Runtime-string constructions in candidate','']
        ss=runtime_strings_in_window(d,st,en)
        if not ss: lines.append('- none recovered with known relocation')
        for x,y,v,f,s in ss[:80]: lines.append(f'- `0x{x:08X}/0x{y:08X}` runtime `0x{v:08X}` -> file `0x{f:08X}`: `{s[:140]}`')
        lines.append('')
    lines += ['## Relationship between the two anchors','']
    (s0,e0),(s1,e1)=bounds
    lines.append(f'- same nearest-prologue function: `{s0==s1}`')
    lines.append(f'- first bounds: `0x{s0:08X}..0x{e0:08X}`')
    lines.append(f'- second bounds: `0x{s1:08X}..0x{e1:08X}`')
    lines.append(f'- anchor distance: `0x{ANCHORS[1]-ANCHORS[0]:X}`')
    lines += ['', '## Interpretation boundary','', 'The 0x78C immediate is only promoted to an MCC-object producer when surrounding data flow shows it is used as the size of a buffer/object that is populated and then reaches the closed CtrlMultiAxis/RDMA path. No renderer behavior is changed by this trace.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
