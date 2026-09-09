#!/usr/bin/env python3
"""Focused Leica M11-P R2YS descriptor-selector search.

This intentionally replaces broad parser archaeology with one narrow question:
find A32 functions that treat the SAME pointer as the verified 20-byte R2YS
 descriptor and then either iterate it or compare its +0x10 category field.

Verified descriptor fields:
  +0x04 descriptor_size
  +0x08 map_size
  +0x0c map_offset (relative to R2YS base)
  +0x10 category

High-confidence candidate requirements:
  - loads from +4,+8,+0xc,+0x10 through the same base register, AND
  - either advances that same descriptor base by the loaded +4 size, OR
  - compares the register loaded from +0x10 directly with 15 or 20.

The report also notes ADD operations that consume the +0xc map-offset register,
which is the expected bridge to `resource_base + map_offset`.
"""
from __future__ import annotations

import argparse, hashlib, re
from dataclasses import dataclass, field
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

CODE_START=0x01000000
CODE_END=0x02000000
EXPECTED=EXPECTED_UNPACKED_SHA

REG=r'(?:r(?:1[0-2]|[0-9])|ip|fp|lr|sp)'

@dataclass
class Fn:
    start:int
    end:int=0
    ins:list=field(default_factory=list)


def is_prologue(i):
    return i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)

def ldr_mem(i):
    if not i.mnemonic.startswith('ldr'): return None
    m=re.match(rf'^({REG}), \[({REG})(?:, #(-?0x[0-9a-f]+|-?[0-9]+))?\]',i.op_str)
    if not m:return None
    return m.group(1),m.group(2),int(m.group(3),0) if m.group(3) else 0

def cmp_imm(i):
    if i.mnemonic!='cmp':return None
    m=re.match(rf'^({REG}), #(0x[0-9a-f]+|[0-9]+)$',i.op_str)
    return (m.group(1),int(m.group(2),0)) if m else None

def add_regs(i):
    if not i.mnemonic.startswith('add'):return None
    p=[x.strip() for x in i.op_str.split(',')]
    if len(p)!=3:return None
    if re.fullmatch(REG,p[0]) and re.fullmatch(REG,p[1]) and re.fullmatch(REG,p[2]):
        return tuple(p)
    return None

def functions(data):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    cur=None;out=[]
    for i in md.disasm(data[CODE_START:min(CODE_END,len(data))],CODE_START):
        if is_prologue(i):
            if cur is not None:
                cur.end=i.address;out.append(cur)
            cur=Fn(i.address)
        if cur is not None:
            cur.ins.append(i)
            if len(cur.ins)>5000:
                cur.end=i.address+4;out.append(cur);cur=None
    if cur is not None:
        cur.end=cur.ins[-1].address+4;out.append(cur)
    return out

def analyze(fn):
    bybase={}
    for idx,i in enumerate(fn.ins):
        x=ldr_mem(i)
        if not x:continue
        dst,base,off=x
        if off not in (4,8,12,16):continue
        bybase.setdefault(base,{}).setdefault(off,[]).append((idx,i.address,dst))
    rows=[]
    for base,loads in bybase.items():
        if not all(o in loads for o in (4,8,12,16)):continue
        size_regs={(idx,reg) for idx,_,reg in loads[4]}
        off_regs={(idx,reg) for idx,_,reg in loads[12]}
        cat_regs={(idx,reg) for idx,_,reg in loads[16]}
        iter_hits=[];mapadd_hits=[];cat_hits=[]
        for idx,i in enumerate(fn.ins):
            ar=add_regs(i)
            if ar:
                dst,a,b=ar
                for li,r in size_regs:
                    if idx>li and idx-li<=40 and dst==base and (a==base and b==r or b==base and a==r):
                        iter_hits.append((i.address,r))
                for li,r in off_regs:
                    if idx>li and idx-li<=40 and r in (a,b):
                        other=b if a==r else a
                        mapadd_hits.append((i.address,r,other,dst))
            ci=cmp_imm(i)
            if ci and ci[1] in (15,20):
                reg,val=ci
                for li,r in cat_regs:
                    if idx>li and idx-li<=32 and reg==r:
                        cat_hits.append((i.address,val,r))
        if iter_hits or cat_hits:
            score=100
            score += 30 if iter_hits else 0
            score += 30 if cat_hits else 0
            score += 15 if mapadd_hits else 0
            rows.append((score,base,loads,iter_hits,mapadd_hits,cat_hits))
    return rows

def fmt_ins(fn,center=None,radius=0x90):
    if center is None:return fn.ins[:120]
    return [i for i in fn.ins if center-radius<=i.address<=center+radius]

def report(data):
    h=hashlib.sha256(data).hexdigest()
    if h!=EXPECTED:raise ValueError(f'unexpected SHA {h}')
    hits=[]
    for fn in functions(data):
        for row in analyze(fn):hits.append((row[0],fn,row))
    hits.sort(key=lambda z:(-z[0],z[1].start,z[2][1]))
    lines=['# M11-P fast R2YS descriptor-selector trace','',f'- SHA-256: `{h}`',f'- qualifying same-base candidates: **{len(hits)}**','',
           'Qualification requires the verified descriptor offsets `+4,+8,+0xc,+0x10` through one base register plus descriptor-size iteration and/or direct Category 15/20 comparison.','']
    lines += ['| score | function | descriptor base | size-iteration | map-offset ADD | Cat15/20 direct cmp |','|---:|---|---|---|---|---|']
    for score,fn,row in hits[:40]:
        _,base,loads,iters,madds,cats=row
        lines.append(f"| {score} | `0x{fn.start:08x}` | `{base}` | {len(iters)} | {len(madds)} | {','.join(str(v) for _,v,_ in cats) or '-'} |")
    for score,fn,row in hits[:16]:
        _,base,loads,iters,madds,cats=row
        centers=[a for a,_ in iters]+[a for a,_,_,_ in madds]+[a for a,_,_ in cats]
        center=min(centers) if centers else fn.start
        lines += ['',f'## candidate `0x{fn.start:08x}` score `{score}`',
                  f'- descriptor base register: `{base}`',
                  f'- +4 loads: `{[(hex(a),r) for _,a,r in loads[4]]}`',
                  f'- +8 loads: `{[(hex(a),r) for _,a,r in loads[8]]}`',
                  f'- +0xc loads: `{[(hex(a),r) for _,a,r in loads[12]]}`',
                  f'- +0x10 loads: `{[(hex(a),r) for _,a,r in loads[16]]}`',
                  f'- descriptor-size iteration hits: `{[(hex(a),r) for a,r in iters]}`',
                  f'- map-offset ADD hits: `{[(hex(a),r,other,dst) for a,r,other,dst in madds]}`',
                  f'- direct category hits: `{[(hex(a),v,r) for a,v,r in cats]}`','```text']
        for i in fmt_ins(fn,center,0xc0):lines.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip())
        lines.append('```')
    lines += ['', '## Decision rule','',
              '- A candidate with **same-base descriptor geometry + size iteration + map-offset addition + direct Cat15/20 compare** is the preferred next trace target.',
              '- If none exists, stop searching for literal category branches: the selector is likely table-driven. Then trace functions that satisfy geometry + iteration + map-offset addition and inspect the value passed downstream as category.',
              '- No renderer change follows from this report alone.','']
    return '\n'.join(lines)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
