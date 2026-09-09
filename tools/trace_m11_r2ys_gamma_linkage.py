#!/usr/bin/env python3
"""Trace direct Leica M11-P references linking R2YS Category 15/20 to runtime code.

This is a primary-evidence xref probe. It parses the canonical embedded R2YS
resource, resolves the exact Category-15/20 descriptors/maps, and searches the
full unpacked image for multiple address representations:

- raw file offsets;
- R2YS-relative offsets;
- proven data-affine virtual pointers (raw + 0x3efd2a98);
- descriptor raw/relative/virtual addresses;
- MOVW/MOVT constructions of those values in the A32 code region.

It also probes the R2YS marker and `img/data/r2y.bin` path so a negative direct
map-xref result can pivot toward the dynamic descriptor/category loader.
No BB06 opcode is equated with an R2YS category.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

EXPECTED=EXPECTED_UNPACKED_SHA
DATA_BASE=0x3EFD2A98
CODE_START=0x01000000
CODE_END=0x02000000
TARGET_CATEGORIES=(15,20)
PATH=b'img/data/r2y.bin\x00'


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def all_word_hits(d,v):
    n=struct.pack('<I',v&0xffffffff); out=[]; p=0
    while True:
        p=d.find(n,p)
        if p<0:return out
        if not(p&3):out.append(p)
        p+=1

def is_prologue(i):
    return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,off,radius=0x1000):
    if not(CODE_START<=off<min(CODE_END,len(d))):return None
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); best=None
    for p in range(max(CODE_START,off-radius)&~3,off+1,4):
        i=next(md.disasm(d[p:p+4],p),None)
        if is_prologue(i):best=p
    return best

def disasm_window(d,off,radius=0x30):
    if not(CODE_START<=off<min(CODE_END,len(d))):return []
    s=max(CODE_START,off-radius)&~3; e=min(CODE_END,len(d),off+radius+4)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    return [f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip() for i in md.disasm(d[s:e],s)]

def parse_imm(op):
    m=re.search(r'#(0x[0-9a-f]+|[0-9]+)',op)
    return int(m.group(1),0) if m else None

def movw_movt_hits(d,targets):
    """Find nearby MOVW/MOVT pairs that construct exact 32-bit target values."""
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    ins=list(md.disasm(d[CODE_START:min(CODE_END,len(d))],CODE_START))
    out=defaultdict(list)
    recent={}
    for idx,i in enumerate(ins):
        if i.mnemonic=='movw':
            parts=[x.strip() for x in i.op_str.split(',')]
            if len(parts)==2 and parts[0].startswith('r'):
                v=parse_imm(i.op_str)
                if v is not None:recent[parts[0]]=(idx,i.address,v&0xffff)
        elif i.mnemonic=='movt':
            parts=[x.strip() for x in i.op_str.split(',')]
            if len(parts)==2 and parts[0] in recent:
                j,a,lo=recent[parts[0]]; hi=parse_imm(i.op_str)
                if hi is not None and idx-j<=12:
                    v=((hi&0xffff)<<16)|lo
                    if v in targets:out[v].append((a,i.address,parts[0]))
        # expire very old pairs cheaply
        for r,(j,_,_) in list(recent.items()):
            if idx-j>16:recent.pop(r,None)
    return out

def descriptor_rows(data,base,descs):
    rows=[]
    for cat in TARGET_CATEGORIES:
        matches=[x for x in descs if x['category']==cat]
        for x in matches:
            desc_abs=base+x['descriptor_rel']
            rows.append({
                'category':cat,'index':x['index'],'flags':x['flags_hex'],
                'descriptor_size':x['descriptor_size'],'dependencies':x['dependencies_s32'],
                'descriptor_abs':desc_abs,'descriptor_rel':x['descriptor_rel'],
                'descriptor_virtual':(desc_abs+DATA_BASE)&0xffffffff,
                'map_abs':x['map_offset_abs'],'map_rel':x['map_offset_rel'],
                'map_virtual':(x['map_offset_abs']+DATA_BASE)&0xffffffff,
                'map_size':x['map_size'],
                'map_sha256':hashlib.sha256(data[x['map_offset_abs']:x['map_offset_abs']+x['map_size']]).hexdigest(),
            })
    return rows

def report(data):
    h=hashlib.sha256(data).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    base,size,dbrel,descs=parse_r2y(data)
    rows=descriptor_rows(data,base,descs)
    if {r['category'] for r in rows}!={15,20}:raise ValueError('Category 15/20 inventory changed')
    path_raw=data.find(PATH)
    if path_raw<0:raise ValueError('r2y path not found')

    named={
        'R2YS raw':base,
        'R2YS virtual':(base+DATA_BASE)&0xffffffff,
        'r2y path raw':path_raw,
        'r2y path virtual':(path_raw+DATA_BASE)&0xffffffff,
    }
    for r in rows:
        p=f"Cat{r['category']}"
        named[f'{p} descriptor raw']=r['descriptor_abs']
        named[f'{p} descriptor rel']=r['descriptor_rel']
        named[f'{p} descriptor virtual']=r['descriptor_virtual']
        named[f'{p} map raw']=r['map_abs']
        named[f'{p} map rel']=r['map_rel']
        named[f'{p} map virtual']=r['map_virtual']

    values=set(named.values())
    mh=movw_movt_hits(data,values)
    lines=['# M11-P R2A R2YS Category 15/20 direct-linkage trace','',f'- SHA-256: `{h}`',f'- proven data affine: `0x{DATA_BASE:08x}`',f'- R2YS raw: `0x{base:08x}`; size `{size}`; DB header rel `0x{dbrel:x}`',f'- `img/data/r2y.bin` raw: `0x{path_raw:08x}`; virtual `0x{(path_raw+DATA_BASE)&0xffffffff:08x}`','']
    lines += ['## Exact Category 15/20 descriptors','', '| cat | idx | flags | descriptor raw/rel | map raw/rel | map virtual | size | dependencies | map SHA-256 |','|---:|---:|---|---|---|---|---:|---|---|']
    for r in rows:
        lines.append(f"| {r['category']} | {r['index']} | `{r['flags']}` | `0x{r['descriptor_abs']:08x}` / `0x{r['descriptor_rel']:x}` | `0x{r['map_abs']:08x}` / `0x{r['map_rel']:x}` | `0x{r['map_virtual']:08x}` | {r['map_size']} | `{r['dependencies']}` | `{r['map_sha256']}` |")

    lines += ['', '## Exact 32-bit word references','']
    for name,v in named.items():
        hits=all_word_hits(data,v)
        lines += [f'### {name} = `0x{v:08x}`',f'- aligned exact word hits: `{len(hits)}`']
        for off in hits[:40]:
            pro=nearest_prologue(data,off)
            loc='code' if CODE_START<=off<min(CODE_END,len(data)) else 'data/non-primary-code'
            lines.append(f'- raw `0x{off:08x}` ({loc}); nearest prologue `{("0x%08x"%pro) if pro is not None else "-"}`')
            if loc=='code':
                lines += ['```text'];lines.extend(disasm_window(data,off));lines+=['```']
        lines.append('')

    lines += ['## MOVW/MOVT exact constant constructions','']
    for name,v in named.items():
        hits=mh.get(v,[])
        lines.append(f'- {name} `0x{v:08x}`: `{len(hits)}` constructions')
        for a,b,r in hits[:30]:lines.append(f'  - `0x{a:08x}` MOVW .. `0x{b:08x}` MOVT in `{r}`; nearest prologue `{("0x%08x"%nearest_prologue(data,a)) if nearest_prologue(data,a) is not None else "-"}`')

    direct_map_refs=sum(len(all_word_hits(data,r['map_virtual']))+len(mh.get(r['map_virtual'],[])) for r in rows)
    direct_raw_refs=sum(len(all_word_hits(data,r['map_abs']))+len(mh.get(r['map_abs'],[])) for r in rows)
    lines += ['', '## Interpretation boundary','',f'- direct Cat15/20 virtual-map references/constructions found by this probe: `{direct_map_refs}`',f'- direct Cat15/20 raw-map references/constructions found by this probe: `{direct_raw_refs}`','- A zero result does **not** mean the maps are unused. The R2YS database stores map offsets in descriptors and runtime code can compute `resource_base + map_offset` dynamically. In that case the next evidence target is the R2YS descriptor/category parser/selector, not a literal map-address xref.','- BB06 command numbers are a separate namespace and are not used as R2YS category evidence.','']
    return '\n'.join(lines)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
