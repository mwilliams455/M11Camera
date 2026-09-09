#!/usr/bin/env python3
"""Fast, origin-aware Leica M11-P R2YS descriptor-selector search.

The previous register-only scan was intentionally conservative but GCC's heavy
reuse of r3 produced false matches. This pass tracks a descriptor pointer by its
saved frame/local origin instead: e.g. `ldr r3,[fp,#-0x20]` followed by field
loads through r3. Only fields reached from the SAME saved pointer are grouped.

Verified R2YS descriptor layout:
  +0x04 descriptor_size
  +0x08 map_size
  +0x0c map_offset (relative to R2YS base)
  +0x10 category

A strong candidate must recover all four fields through one pointer origin and
show at least one of:
  * descriptor iteration: ptr += descriptor_size, then store ptr back;
  * direct compare of the +0x10 value with 15 or 20;
  * use of the +0x0c value in an ADD (candidate resource_base + map_offset).
"""
from __future__ import annotations
import argparse, hashlib, re
from dataclasses import dataclass, field
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

CODE_START=0x01000000; CODE_END=0x02000000; EXPECTED=EXPECTED_UNPACKED_SHA
REG=r'(?:r(?:1[0-2]|[0-9])|ip|fp|lr|sp)'

@dataclass
class Fn:
    start:int
    ins:list=field(default_factory=list)


def is_prologue(i):
    return i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def memop(i,prefix):
    if not i.mnemonic.startswith(prefix):return None
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
    if len(p)==3 and all(re.fullmatch(REG,x) for x in p):return tuple(p)
    return None

def functions(data):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    out=[];cur=None
    for i in md.disasm(data[CODE_START:min(CODE_END,len(data))],CODE_START):
        if is_prologue(i):
            if cur:out.append(cur)
            cur=Fn(i.address)
        if cur:
            cur.ins.append(i)
            if len(cur.ins)>5000:out.append(cur);cur=None
    if cur:out.append(cur)
    return out

def origin_field_loads(fn):
    """Return (origin, fieldoff) -> [(idx,address,dst,ptrreg)].

    Origin is a stable saved-pointer slot `(fp|sp, offset)`. We recognize the
    common GCC form `ldr ptr,[fp,#slot]` then within <=3 instructions
    `ldr value,[ptr,#field]`.
    """
    out={}
    ins=fn.ins
    for idx,i in enumerate(ins):
        p=memop(i,'ldr')
        if not p:continue
        ptr,frame,slot=p
        if frame not in ('fp','sp'):continue
        for j in range(idx+1,min(len(ins),idx+5)):
            x=memop(ins[j],'ldr')
            if x and x[1]==ptr and x[2] in (4,8,12,16):
                origin=(frame,slot);off=x[2]
                out.setdefault((origin,off),[]).append((j,ins[j].address,x[0],ptr,idx,i.address))
            # if ptr is overwritten, stop following it
            if j>idx+1:
                y=memop(ins[j],'ldr')
                if y and y[0]==ptr and y[1]!=ptr:break
    return out

def analyze(fn):
    fl=origin_field_loads(fn.ins and fn or fn)
    origins=sorted({origin for origin,_ in fl})
    rows=[];ins=fn.ins
    for origin in origins:
        loads={o:fl.get((origin,o),[]) for o in (4,8,12,16)}
        if not all(loads[o] for o in loads):continue
        iters=[];mapadds=[];cats=[]
        frame,slot=origin
        # direct category compare from exact loaded register
        for li,_,reg,_,_,_ in loads[16]:
            for j in range(li+1,min(len(ins),li+18)):
                ci=cmp_imm(ins[j])
                if ci and ci[0]==reg and ci[1] in (15,20):cats.append((ins[j].address,ci[1],reg))
                # conservative clobber stop
                mo=memop(ins[j],'ldr')
                if mo and mo[0]==reg:break
        # map offset consumed in nearby ADD
        for li,_,reg,_,_,_ in loads[12]:
            for j in range(li+1,min(len(ins),li+18)):
                ar=add_regs(ins[j])
                if ar and reg in ar[1:]:
                    other=ar[2] if ar[1]==reg else ar[1]
                    mapadds.append((ins[j].address,reg,other,ar[0]))
                mo=memop(ins[j],'ldr')
                if mo and mo[0]==reg:break
        # ptr += descriptor_size and save pointer back to SAME origin slot
        for li,_,sizereg,ptrreg,pi,_ in loads[4]:
            for j in range(li+1,min(len(ins),li+28)):
                ar=add_regs(ins[j])
                if not ar:continue
                dst,a,b=ar
                if dst==ptrreg and ((a==ptrreg and b==sizereg) or (b==ptrreg and a==sizereg)):
                    for k in range(j+1,min(len(ins),j+10)):
                        st=memop(ins[k],'str')
                        if st and st[0]==ptrreg and st[1]==frame and st[2]==slot:
                            iters.append((ins[j].address,ins[k].address,ptrreg,sizereg))
                            break
        if iters or mapadds or cats:
            score=100+(40 if iters else 0)+(40 if cats else 0)+(25 if mapadds else 0)
            rows.append((score,origin,loads,iters,mapadds,cats))
    return rows

def report(data):
    h=hashlib.sha256(data).hexdigest()
    if h!=EXPECTED:raise ValueError(h)
    hits=[]
    for fn in functions(data):
        for row in analyze(fn):hits.append((row[0],fn,row))
    hits.sort(key=lambda z:(-z[0],z[1].start,z[2][1]))
    lines=['# M11-P origin-aware R2YS descriptor selector trace','',f'- SHA-256: `{h}`',f'- qualifying pointer-origin candidates: **{len(hits)}**','']
    lines += ['| score | function | saved pointer origin | iteration | map-offset ADD | direct Cat15/20 |','|---:|---|---|---:|---:|---|']
    for score,fn,row in hits[:40]:
        _,origin,loads,iters,madds,cats=row
        lines.append(f"| {score} | `0x{fn.start:08x}` | `{origin[0]}{origin[1]:+d}` | {len(iters)} | {len(madds)} | {','.join(str(v) for _,v,_ in cats) or '-'} |")
    for score,fn,row in hits[:12]:
        _,origin,loads,iters,madds,cats=row
        centers=[a for a,_,_,_ in iters]+[a for a,_,_,_ in madds]+[a for a,_,_ in cats]
        center=min(centers) if centers else fn.start
        lines += ['',f'## candidate `0x{fn.start:08x}` score `{score}` origin `{origin[0]}{origin[1]:+d}`',
                  f'- field loads: `{ {hex(o):[(hex(a),r,p) for _,a,r,p,_,_ in loads[o]] for o in (4,8,12,16)} }`',
                  f'- iteration: `{[(hex(a),hex(s),p,r) for a,s,p,r in iters]}`',
                  f'- map-offset ADD: `{[(hex(a),r,other,dst) for a,r,other,dst in madds]}`',
                  f'- direct category compares: `{[(hex(a),v,r) for a,v,r in cats]}`','```text']
        for i in fn.ins:
            if center-0xb0<=i.address<=center+0xb0:lines.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}'.rstrip())
        lines.append('```')
    lines += ['', '## Bounded decision','',
              '- If one candidate has iteration + map-offset ADD + Cat15/20 compare, trace only that function next.',
              '- If candidates have iteration + map-offset ADD but no literal Cat15/20 compare, treat selection as table-driven and inspect only the top such function downstream.',
              '- If no credible candidate remains, stop this loader line and rely on runtime instrumentation/capture rather than more static broad scans.',
              '- Renderer remains frozen.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
