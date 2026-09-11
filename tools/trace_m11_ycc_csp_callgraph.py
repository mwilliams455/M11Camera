#!/usr/bin/env python3
"""Trace Leica M11-P YC and CSP wrapper ancestry and local call order.

This is configuration-path evidence only.  It is useful for showing whether
Leica treats YC conversion and CSP as adjacent parts of the same R2Y setup,
but CPU call order is not promoted to silicon pixel-stage order by itself.
"""
from __future__ import annotations
import argparse, hashlib, struct
from collections import defaultdict, deque
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
YCC_WRAPPER=0x0172DFC0
YCC_SETTER=0x01B624AC
CSP_SETTER=0x01B68B80
CSP_CALLSITE=0x01731DB0


def u32(d,p): return struct.unpack_from('<I',d,p)[0]
def push_lr(w): return (w & 0xFFFF4000)==0xE92D4000

def entry_before(d,p,back=0x3000):
    lo=max(0,p-back)&~3; out=None
    for q in range(lo,p+1,4):
        if push_lr(u32(d,q)): out=q
    return out if out is not None else lo

def bl_target(p,w):
    if ((w>>28)&0xF)==0xF or ((w>>25)&7)!=5 or ((w>>24)&1)==0: return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=1<<24
    return (p+8+(imm<<2))&0xFFFFFFFF

def index_calls(d):
    by_target=defaultdict(list)
    for p in range(0,len(d)&~3,4):
        t=bl_target(p,u32(d,p))
        if t is not None: by_target[t].append(p)
    return by_target

def ancestors(d,by_target,start,depth=4):
    levels={start:0}; q=deque([start]); edges=[]
    while q:
        t=q.popleft(); dep=levels[t]
        if dep>=depth: continue
        for cs in by_target.get(t,[]):
            e=entry_before(d,cs)
            edges.append((e,cs,t,dep+1))
            if e not in levels or dep+1<levels[e]:
                levels[e]=dep+1; q.append(e)
    return levels,edges

def extent(d,e,maxlen=0x4000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for i in md.disasm(d[e:min(len(d),e+maxlen)],e):
        if i.address>e+8 and ((i.mnemonic=='pop' and 'pc' in i.op_str) or (i.mnemonic=='bx' and i.op_str.strip()=='lr')):
            return i.address+4
    return min(len(d),e+maxlen)

def calls_in_function(d,e):
    end=extent(d,e); out=[]
    for p in range(e,end,4):
        t=bl_target(p,u32(d,p))
        if t is not None: out.append((p,t))
    return end,out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args(); d=a.unpacked.read_bytes(); sha=hashlib.sha256(d).hexdigest()
    if sha!=EXPECTED_SHA: raise ValueError(sha)
    by=index_calls(d)
    csp_wrapper=entry_before(d,CSP_CALLSITE)
    ylev,yedges=ancestors(d,by,YCC_WRAPPER,5)
    clev,cedges=ancestors(d,by,csp_wrapper,5)
    common=sorted(set(ylev)&set(clev), key=lambda x:(max(ylev[x],clev[x]),ylev[x]+clev[x],x))
    lines=['# M11-P YC / CSP configuration call graph','',f'- SHA-256: `{sha}`',f'- YC wrapper: `0x{YCC_WRAPPER:08x}` -> setter `0x{YCC_SETTER:08x}`',f'- CSP setter: `0x{CSP_SETTER:08x}`; known callsite `0x{CSP_CALLSITE:08x}`',f'- CSP enclosing wrapper entry: `0x{csp_wrapper:08x}`',f'- direct callers YC wrapper: `{[hex(x) for x in by.get(YCC_WRAPPER,[])]}`',f'- direct callers CSP wrapper: `{[hex(x) for x in by.get(csp_wrapper,[])]}`','']
    lines += ['## YC ancestry','']
    for e,cs,t,dep in yedges: lines.append(f'- depth {dep}: function `0x{e:08x}` callsite `0x{cs:08x}` -> `0x{t:08x}`')
    lines += ['','## CSP ancestry','']
    for e,cs,t,dep in cedges: lines.append(f'- depth {dep}: function `0x{e:08x}` callsite `0x{cs:08x}` -> `0x{t:08x}`')
    lines += ['','## Common ancestors','']
    if not common: lines.append('None within depth 5.')
    for e in common[:20]:
        end,calls=calls_in_function(d,e)
        lines += [f'### `0x{e:08x}`',f'- YC depth `{ylev[e]}`; CSP depth `{clev[e]}`; extent `0x{e:08x}..0x{end:08x}`']
        interesting=[]
        ytargets={x for x in ylev}; ctargets={x for x in clev}
        for cs,t in calls:
            tags=[]
            if t in ytargets: tags.append(f'YC-path depth {ylev[t]}')
            if t in ctargets: tags.append(f'CSP-path depth {clev[t]}')
            if tags: interesting.append((cs,t,', '.join(tags)))
        for cs,t,tags in interesting: lines.append(f'- call `0x{cs:08x}` -> `0x{t:08x}` ({tags})')
        lines.append('')
    lines += ['## Interpretation boundary','', 'A common parent and stable YC-before-CSP configuration call order support adjacency in Leica R2Y setup, but this report does not claim hardware pixel ordering. Pixel-domain placement requires independent hardware/domain evidence.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)); print(a.output)
if __name__=='__main__': main()
