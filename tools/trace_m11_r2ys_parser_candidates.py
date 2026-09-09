#!/usr/bin/env python3
"""Discover Leica M11-P runtime R2YS descriptor/category parser candidates.

Direct Cat15/Cat20 map-address xrefs are absent. The database therefore needs
an evidence-driven dynamic-parser search. This pass ranks A32 function families
by the exact descriptor shape recovered from `img/data/r2y.bin`:

  +0x00 flags
  +0x04 descriptor_size
  +0x08 map_size
  +0x0c map_offset (relative to R2YS)
  +0x10 category

It also finds code references/constructions of the literal R2YS/R2YE marker
words and contexts where a value loaded from +0x10 is compared with Category 15
or 20. Candidates are structural only until their data source is tied to R2YS.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import defaultdict, deque
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

EXPECTED=EXPECTED_UNPACKED_SHA
CODE_START=0x01000000
CODE_END=0x02000000
R2YS_WORD=0x53593252
R2YE_WORD=0x45593252
MARKERS={R2YS_WORD:'R2YS',R2YE_WORD:'R2YE'}


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def is_prologue(i):
    return i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def mem_load(i):
    if not i.mnemonic.startswith('ldr'):return None
    m=re.search(r'^(r\d+|ip|fp|lr), \[(r\d+|ip|fp|sp|lr|pc)(?:, #(-?0x[0-9a-f]+|-?[0-9]+))?\]',i.op_str)
    if not m:return None
    dst,base,offs=m.groups();return dst,base,int(offs,0) if offs else 0
def cmp_imm(i):
    if i.mnemonic!='cmp':return None
    m=re.match(r'(r\d+|ip|fp|lr), #(0x[0-9a-f]+|[0-9]+)$',i.op_str)
    return (m.group(1),int(m.group(2),0)) if m else None
def imm16(i):
    m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',i.op_str)
    return int(m.group(1),0) if m else None
def context(d,a,r=0x38):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    s=max(CODE_START,a-r)&~3;e=min(CODE_END,len(d),a+r+4)
    return [f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip() for i in md.disasm(d[s:e],s)]
def nearest_prologue(d,a,r=0x1000):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for p in range(max(CODE_START,a-r)&~3,a+1,4):
        i=next(md.disasm(d[p:p+4],p),None)
        if i and is_prologue(i):best=p
    return best

def marker_literal_xrefs(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START):
        x=mem_load(i)
        if not x or x[1]!='pc':continue
        lit=i.address+8+x[2]
        if 0<=lit<=len(d)-4:
            v=u32(d,lit)
            if v in MARKERS:out.append((i.address,lit,v))
    return out

def marker_mov_pairs(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;recent={};out=[];idx=0
    for i in md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START):
        idx+=1
        if i.mnemonic=='movw':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2:
                v=imm16(i)
                if v is not None:recent[p[0]]=(idx,i.address,v&0xffff)
        elif i.mnemonic=='movt':
            p=[x.strip() for x in i.op_str.split(',')]
            if len(p)==2 and p[0] in recent:
                j,a,lo=recent[p[0]];hi=imm16(i)
                if hi is not None and idx-j<=12:
                    v=((hi&0xffff)<<16)|lo
                    if v in MARKERS:out.append((a,i.address,p[0],v))
        for r,(j,_,_) in list(recent.items()):
            if idx-j>16:recent.pop(r,None)
    return out

def rank_descriptor_functions(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    candidates=[]; current=None
    def fresh(a):return {'start':a,'end':a,'bases':defaultdict(set),'cat_loads':[], 'cat_cmps':[], 'all_cmps':[], 'ins':0}
    def flush(c):
        if not c:return
        bestbase=None;bestscore=-1;bestoffs=set()
        for b,offs in c['bases'].items():
            score=sum(1 for x in (0,4,8,12,16) if x in offs)
            if score>bestscore:bestscore=score;bestbase=b;bestoffs=offs
        # Require at least descriptor_size/map_offset/category geometry.
        if bestscore>=3 and 4 in bestoffs and 12 in bestoffs and 16 in bestoffs:
            score=bestscore*10
            if 8 in bestoffs:score+=5
            if 0 in bestoffs:score+=3
            if any(v in (15,20) for _,v in c['all_cmps']):score+=12
            candidates.append((score,c,bestbase,set(bestoffs)))
    for i in md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START):
        if is_prologue(i):
            flush(current);current=fresh(i.address)
        if current is None:continue
        current['end']=i.address;current['ins']+=1
        x=mem_load(i)
        if x and x[1]!='pc':
            dst,b,off=x;current['bases'][b].add(off)
            if off==16:current['cat_loads'].append((i.address,dst,b))
        ci=cmp_imm(i)
        if ci:current['all_cmps'].append((i.address,ci[1]))
        if current['ins']>3000:
            flush(current);current=None
    flush(current)
    candidates.sort(key=lambda x:(-x[0],x[1]['start']))
    return candidates[:80]
def category_compare_contexts(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    q=deque(maxlen=20);out=[]
    for i in md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START):
        x=mem_load(i)
        if x and x[2]==16 and x[1]!='pc':q.append((i.address,x[0],x[1]))
        ci=cmp_imm(i)
        if ci and ci[1] in (15,20):
            reg=ci[0]
            src=next((z for z in reversed(q) if z[1]==reg and i.address-z[0]<=0x80),None)
            if src:out.append((src[0],i.address,src[2],ci[1]))
        while q and i.address-q[0][0]>0x100:q.popleft()
    return out

def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    lit=marker_literal_xrefs(d);mov=marker_mov_pairs(d);cats=category_compare_contexts(d);ranked=rank_descriptor_functions(d)
    marker_hits=[]
    for v,name in MARKERS.items():
        n=struct.pack('<I',v);p=0
        while True:
            p=d.find(n,p)
            if p<0:break
            if not(p&3):marker_hits.append((name,p))
            p+=1
    lines=['# M11-P R2A dynamic R2YS parser candidate trace','',f'- SHA-256: `{h}`','- descriptor geometry sought: `+0 flags, +4 dsize, +8 map_size, +0xc map_offset, +0x10 category`','']
    lines += ['## Literal marker occurrences','']
    for name,p in marker_hits[:100]:lines.append(f'- `{name}` word at raw `0x{p:08x}`')
    lines += ['', '## A32 PC-relative marker literal references','',f'- count: `{len(lit)}`']
    for a,l,v in lit:
        lines.append(f'- `0x{a:08x}` loads `{MARKERS[v]}` from literal `0x{l:08x}`; prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
        lines+=['```text'];lines.extend(context(d,a));lines+=['```']
    lines += ['', '## MOVW/MOVT marker constructions','',f'- count: `{len(mov)}`']
    for a,b,r,v in mov:lines.append(f'- `{MARKERS[v]}`: `0x{a:08x}`..`0x{b:08x}` in `{r}`; prologue `{("0x%08x"%nearest_prologue(d,a)) if nearest_prologue(d,a) is not None else "-"}`')
    lines += ['', '## Direct `+0x10 category` load followed by compare 15/20','',f'- count: `{len(cats)}`']
    for la,ca,b,v in cats:
        lines.append(f'- load `0x{la:08x}` from `[{b},#0x10]`, compare Category `{v}` at `0x{ca:08x}`; prologue `{("0x%08x"%nearest_prologue(d,la)) if nearest_prologue(d,la) is not None else "-"}`')
        lines+=['```text'];lines.extend(context(d,la,0x50));lines+=['```']
    lines += ['', '## Ranked descriptor-shape function families','', '| score | prologue | best base | observed offsets | category-15/20 cmp nearby |','|---:|---|---|---|---|']
    for score,c,b,offs in ranked:
        special=any(v in (15,20) for _,v in c['all_cmps'])
        lines.append(f"| {score} | `0x{c['start']:08x}` | `{b}` | `{sorted(offs)}` | {'yes' if special else 'no'} |")
    for score,c,b,offs in ranked[:20]:
        lines += ['',f"### candidate `0x{c['start']:08x}` score `{score}`",'```text'];lines.extend(context(d,c['start']+0x30,0x90));lines+=['```']
    lines += ['', '## Interpretation boundary','', 'Marker references identify resource-envelope parsing only if surrounding code validates R2YS/R2YE structure. Descriptor-shape candidates identify the recovered 20-byte descriptor layout only after their data source is tied to the R2YS resource. A compare against integer 15 or 20 alone is not category evidence.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
