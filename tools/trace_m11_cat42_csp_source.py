#!/usr/bin/env python3
"""Trace Leica Category-42 source selection into the Milbeaut CSP block.

Pinned primary-firmware path:
  CSP wrapper             0x01731970
  category lookup call    0x01731b34 -> 0x0178d0a8
  generic lookup wrapper  0x0178d0a8 -> init 0x0178a9ac -> core 0x0178c89c
  CSP hardware setter     0x01731db0 -> 0x01b68b80

The CSP wrapper constructs an 0x58-byte request with category 0x2a (42), obtains
one parameter record, copies its 44 bytes field-for-field into a local CSP
control structure, then programs the proven Milbeaut CSP register footprint.
This probe expands the generic lookup core and database init path. It changes no
renderer behaviour and makes no assumption about the internal CSP pixel math.
"""
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_FP, ARM_REG_R11
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

FUNC=0x01731970
LOOKUP_CALL=0x01731B34
LOOKUP=0x0178D0A8
DBINIT=0x0178A9AC
CORE=0x0178C89C
CSP_CALL=0x01731DB0
CSP=0x01B68B80


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def branch_target(a,w):
    cond=(w>>28)&0xf; op=(w>>24)&0xf
    if cond==0xf or op not in (0xa,0xb): return None,None
    imm=w&0xffffff
    if imm&0x800000: imm-=1<<24
    return (a+8+(imm<<2))&0xffffffff, ('BL' if op==0xb else 'B')
def fmt(i): return f"0x{i.address:08x}: {i.mnemonic} {i.op_str}".rstrip()

def disasm_function(md,d,entry,max_len=0x8000):
    out=[]
    for i in md.disasm(d[entry:min(len(d),entry+max_len)],entry):
        out.append(i)
        t=(i.mnemonic+' '+i.op_str).lower()
        if len(out)>2 and ((i.mnemonic=='pop' and 'pc' in i.op_str.lower()) or t.startswith('bx lr') or (i.mnemonic.startswith('ldm') and 'pc' in i.op_str.lower())): break
    return out

def xrefs(d,target):
    b=[]; bl=[]; ptr=[]; pth=[]
    for o in range(0,len(d)-3,4):
        w=u32(d,o); t,k=branch_target(o,w)
        if t==target: (bl if k=='BL' else b).append(o)
        if w==target: ptr.append(o)
        if w==(target|1): pth.append(o)
    return b,bl,ptr,pth

def is_fp_minus8_write(i):
    if not i.mnemonic.startswith(('str','stm')): return False
    return any(o.type==ARM_OP_MEM and o.mem.base in (ARM_REG_FP,ARM_REG_R11) and o.mem.disp==-8 for o in i.operands)

def movw_movt(ins):
    out=[]
    for a,b in zip(ins,ins[1:]):
        if a.mnemonic!='movw' or b.mnemonic!='movt': continue
        aa=[x.strip() for x in a.op_str.split(',')]; bb=[x.strip() for x in b.op_str.split(',')]
        if len(aa)!=2 or len(bb)!=2 or aa[0]!=bb[0]: continue
        try: lo=int(aa[1].replace('#',''),0); hi=int(bb[1].replace('#',''),0)
        except ValueError: continue
        out.append((a.address,aa[0],((hi&0xffff)<<16)|(lo&0xffff)))
    return out

def ascii_near(d,v):
    if not 0<=v<len(d): return ''
    lo=v; hi=v
    while lo>0 and v-lo<120 and 32<=d[lo-1]<127: lo-=1
    while hi<len(d) and hi-v<220 and 32<=d[hi]<127: hi+=1
    return d[lo:hi].decode('ascii','replace') if hi-lo>=5 else ''

def cat42(d):
    base,size,hdr,ds=parse_r2y(d); rows=[]
    for x in ds:
        if x['category']!=42: continue
        dep=x['dependencies_s32']; rows.append((dep[2] if len(dep)>=3 else None,base+x['descriptor_rel'],x['descriptor_size'],x['map_offset_abs'],x['map_size'],dep))
    rows.sort(key=lambda r:999 if r[0] is None else r[0]); return base,size,hdr,rows

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); dig=hashlib.sha256(d).hexdigest()
    if dig!=EXPECTED_UNPACKED_SHA: raise ValueError(dig)
    for site,target in ((LOOKUP_CALL,LOOKUP),(CSP_CALL,CSP)):
        t,k=branch_target(site,u32(d,site))
        if t!=target or k!='BL': raise ValueError(f'pinned call mismatch {site:#x}')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    wrap=list(md.disasm(d[FUNC:CSP_CALL+4],FUNC)); sw=[i for i in wrap if is_fp_minus8_write(i)]
    lookup=disasm_function(md,d,LOOKUP); core=disasm_function(md,d,CORE); dbinit=disasm_function(md,d,DBINIT)
    base,size,hdr,maps=cat42(d)
    cb,cbl,cp,ct=xrefs(d,CORE); ib,ibl,ip,it=xrefs(d,DBINIT)
    L=['# M11-P Category-42 CSP full software-consumer trace','',f'- SHA-256: `{dig}`',f'- R2YS base `0x{base:08x}` size `0x{size:x}` header rel `0x{hdr:x}`',f'- CSP wrapper `0x{FUNC:08x}`',f'- lookup wrapper `0x{LOOKUP:08x}`',f'- database init/ensure `0x{DBINIT:08x}`',f'- lookup core `0x{CORE:08x}`',f'- CSP setter `0x{CSP:08x}`','']
    L += ['## Category-42 records','', '| state | descriptor abs | desc bytes | map abs | map bytes | dependencies |','|---:|---:|---:|---:|---:|---|']
    for st,desc,dsz,ma,msz,dep in maps:
        L.append(f"| {st:+d} | `0x{desc:08x}` | {dsz} | `0x{ma:08x}` | {msz} | `{dep}` |")
    L += ['','## CSP request and returned-record provenance','']
    for i in sw:
        idx=wrap.index(i); L += [f'### `[fp,-8]` write at `0x{i.address:08x}`','```asm',*[fmt(x) for x in wrap[max(0,idx-28):min(len(wrap),idx+12)]],'```','']
    L += ['',f'## Lookup wrapper `0x{LOOKUP:08x}`','```asm',*[fmt(x) for x in lookup],'```','']
    L += [f'## Lookup core `0x{CORE:08x}`',f'- direct B xrefs `{len(cb)}`, BL xrefs `{len(cbl)}`, pointer refs `{len(cp)}`, Thumb-pointer refs `{len(ct)}`','```asm',*[fmt(x) for x in core],'```','']
    L += ['### Lookup-core MOVW/MOVT constants','| insn | reg | value | ASCII if file-like |','|---:|---|---:|---|']
    for ad,r,v in movw_movt(core): L.append(f"| `0x{ad:08x}` | {r} | `0x{v:08x}` | {ascii_near(d,v).replace('|','\\|')[:180]} |")
    L += ['',f'## Database init/ensure `0x{DBINIT:08x}`',f'- direct B xrefs `{len(ib)}`, BL xrefs `{len(ibl)}`, pointer refs `{len(ip)}`, Thumb-pointer refs `{len(it)}`','```asm',*[fmt(x) for x in dbinit],'```','']
    L += ['### Database-init MOVW/MOVT constants','| insn | reg | value | ASCII if file-like |','|---:|---|---:|---|']
    for ad,r,v in movw_movt(dbinit): L.append(f"| `0x{ad:08x}` | {r} | `0x{v:08x}` | {ascii_near(d,v).replace('|','\\|')[:180]} |")
    L += ['','## Interpretation boundary','','The CSP wrapper demonstrably requests category 42 and copies the selected 44-byte record field-for-field to the proven CSP register setter. The core-resolver trace is intended to establish descriptor/dependency matching and returned map-pointer formation. None of this determines the internal Milbeaut CSYKY/chroma-reference/piecewise fixed-point pixel equation.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)); print(a.output)
if __name__=='__main__': main()
