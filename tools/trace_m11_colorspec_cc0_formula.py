#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from collections import deque, defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01500000; END=0x01C00000
ROOT=0x43430188
PREP=0x016EBE14
PROCESS=0x016F2C84
CM=0x016EB010
MATERIALIZE=0x016EB09C
TARGET_OFFS=set(range(0x28,0x54,4)) | {0x50,0x51,0x52,0x53}

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0 <= a <= len(d)-4 else None
def sx(v,b): s=1<<(b-1); return (v^s)-s
def bl_target(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1: return None
    return (a+8+(sx(w&0xffffff,24)<<2)) & 0xffffffff
def is_push(w): return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fstart(d,a,window=0x30000):
    for p in range(a&~3,max(START,(a&~3)-window),-4):
        if is_push(u32(d,p)): return p
    return a&~3
def fend(d,a,limit=0x10000):
    p=(a+4)&~3
    while p<min(END,a+limit):
        if is_push(u32(d,p)): return p
        p+=4
    return min(END,a+limit)
def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def decmov(w,kind):
    tag=w&0x0ff00000; want=0x03000000 if kind=='w' else 0x03400000
    if tag!=want:return None
    return (w>>12)&15,(((w>>4)&0xf000)|(w&0xfff))
def absrefs(d,target):
    out=[]
    for p in range(START,END-4,4):
        m=decmov(u32(d,p),'w')
        if not m: continue
        rd,lo=m
        for q in range(p+4,min(p+48,END-3),4):
            t=decmov(u32(d,q),'t')
            if t and t[0]==rd:
                if ((t[1]<<16)|lo)==target: out.append((p,q,rd))
                break
    return out
def off_in_op(op):
    vals=[]
    for m in re.finditer(r'#-?0x([0-9a-fA-F]+)',op):
        try: vals.append(int(m.group(1),16))
        except: pass
    return vals
def interesting_store(i):
    if i.mnemonic in ('.byte','.word') or not i.mnemonic.startswith(('str','vstr')): return False
    return any(v in TARGET_OFFS for v in off_in_op(i.op_str))
def interesting_load(i):
    if i.mnemonic in ('.byte','.word') or not i.mnemonic.startswith(('ldr','vldr')): return False
    return any(v in TARGET_OFFS for v in off_in_op(i.op_str))
def function_ins(md,d,f):
    e=fend(d,f)
    return list(md.disasm(d[f:e],f)), e

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise SystemExit(f'wrong SHA {h}')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True
    L=['# M11 ColorSpec dynamic CC0 formula trace','',f'- SHA256 `{h}`',
       f'- ColorSpec root `{ROOT:#010x}`',f'- prep `{PREP:#010x}`; process `{PROCESS:#010x}`; CM `{CM:#010x}`; materialize `{MATERIALIZE:#010x}`','']

    # CM top-level ordering.
    L += ['## CM top-level ordering','```asm']
    for i in md.disasm(d[CM:CM+0xB0],CM): L.append(fmt(i))
    L += ['```','']

    # Absolute ColorSpec root references, grouped by function.
    refs=absrefs(d,ROOT); byf=defaultdict(list)
    for p,q,r in refs: byf[fstart(d,p)].append((p,q,r))
    L += ['## Absolute ColorSpec root references','',f'- total references: `{len(refs)}`; functions: `{[hex(x) for x in sorted(byf)]}`','']
    for f,rs in sorted(byf.items()):
        L += [f'### function `{f:#010x}` root refs `{[(hex(p),hex(q),r) for p,q,r in rs]}`','```asm']
        lo=max(f,min(p for p,_,_ in rs)-0x50); hi=min(fend(d,f),max(q for _,q,_ in rs)+0x100)
        for i in md.disasm(d[lo:hi],lo): L.append(fmt(i))
        L += ['```','']

    # Build shallow direct call graph from PREP and PROCESS.
    seeds=[PREP,PROCESS]
    q=deque((x,0) for x in seeds); seen=set(); graph=defaultdict(list)
    MAX_DEPTH=3
    while q:
        f,depth=q.popleft()
        if f in seen or not (START<=f<END): continue
        seen.add(f)
        ins,e=function_ins(md,d,f)
        for i in ins:
            t=bl_target(i.address,u32(d,i.address))
            if t is not None and START<=t<END:
                graph[f].append((i.address,t))
                if depth<MAX_DEPTH: q.append((fstart(d,t),depth+1))
    L += ['## Direct call graph (depth <= 3)','']
    for f in sorted(seen):
        L.append(f'- `{f:#010x}` -> `{[(hex(c),hex(t)) for c,t in graph.get(f,[])]}`')
    L += ['']

    # Functions in graph that touch the CC0 offset family; dump contexts.
    L += ['## CC0-field accesses inside formula call graph','']
    access_count=0
    for f in sorted(seen):
        ins,e=function_ins(md,d,f); idx={x.address:n for n,x in enumerate(ins)}
        hits=[x for x in ins if interesting_store(x) or interesting_load(x)]
        if not hits: continue
        access_count += len(hits)
        L += [f'### function `{f:#010x}` hits `{[(hex(x.address),x.mnemonic,x.op_str) for x in hits]}`','']
        merged=[]
        for x in hits:
            n=idx[x.address]; lo=max(0,n-14); hi=min(len(ins),n+18)
            if merged and lo<=merged[-1][1]: merged[-1]=(merged[-1][0],max(merged[-1][1],hi))
            else: merged.append((lo,hi))
        for lo,hi in merged:
            L += ['```asm']+[fmt(x) for x in ins[lo:hi]]+['```','']
    L += [f'- total target-field accesses in call graph: `{access_count}`','']

    # Root-reference functions are also scanned for CC0 offsets, regardless of graph membership.
    L += ['## CC0-field accesses in all ColorSpec-root reference functions','']
    for f in sorted(byf):
        ins,e=function_ins(md,d,f); hits=[x for x in ins if interesting_store(x) or interesting_load(x)]
        if hits:
            L.append(f'- `{f:#010x}`: `{[(hex(x.address),x.mnemonic,x.op_str) for x in hits]}`')
    L += ['']

    # PREP/PROCESS full bodies: essential for identifying frame inputs and matrix arithmetic.
    for name,f in [('PREP',PREP),('PROCESS',PROCESS)]:
        ins,e=function_ins(md,d,f)
        L += [f'## {name} full body `{f:#010x}`..`{e:#010x}`','```asm']+[fmt(x) for x in ins]+['```','']

    # Call target contexts in PROCESS/PREP, to expose argument setup.
    L += ['## Callsite argument contexts','']
    for f in seeds:
        ins,e=function_ins(md,d,f); idx={x.address:n for n,x in enumerate(ins)}
        for i in ins:
            t=bl_target(i.address,u32(d,i.address))
            if t is None: continue
            n=idx[i.address]
            L += [f'### `{i.address:#010x}` -> `{t:#010x}`','```asm']+[fmt(x) for x in ins[max(0,n-16):min(len(ins),n+6)]]+['```','']

    # Literal floats / obvious fixed constants in graph functions.
    L += ['## Arithmetic / scaling instruction census','']
    keys=('mul','mla','mls','smull','umull','sdiv','udiv','asr','lsr','lsl','ssat','usat','vcvt','vmul','vmla','vdiv','vadd','vsub')
    for f in sorted(seen):
        ins,e=function_ins(md,d,f)
        ah=[x for x in ins if x.mnemonic.startswith(keys)]
        if ah:
            L.append(f'- `{f:#010x}`: `{[(hex(x.address),x.mnemonic,x.op_str) for x in ah[:120]]}`')
    L += ['']

    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
