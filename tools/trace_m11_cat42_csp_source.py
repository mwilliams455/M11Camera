#!/usr/bin/env python3
"""Trace Leica Category-42 selection through the generic R2Y resolver to CSP.

Pinned primary-firmware path:
  CSP wrapper              0x01731970
  category lookup call     0x01731b34 -> 0x0178d0a8
  request debug dumper     0x0178a9ac
  generic resolver core    0x0178c89c
  database-handle lookup   0x0178c3d0
  CSP hardware setter      0x01731db0 -> 0x01b68b80

The CSP wrapper constructs an 0x58-byte request with category 0x2a (42), obtains
one parameter record, copies its 44 bytes field-for-field into a local CSP
control structure, then programs the proven Milbeaut CSP register footprint.
This probe reports Category-42 descriptor flags, expands all resolver alternate
dependency handlers through 0x0178cc80, and traces request[0]=8 into the DB
handle lookup. It changes no renderer behaviour and does not infer CSP pixel math.
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
DEBUG_DUMP=0x0178A9AC
CORE=0x0178C89C
DBGET=0x0178C3D0
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
        out.append(i); t=(i.mnemonic+' '+i.op_str).lower()
        if len(out)>2 and ((i.mnemonic=='pop' and 'pc' in i.op_str.lower()) or t.startswith('bx lr') or (i.mnemonic.startswith('ldm') and 'pc' in i.op_str.lower())): break
    return out
def disasm_range(md,d,start,end): return list(md.disasm(d[start:end],start))
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
        dep=x['dependencies_s32']
        rows.append({
            'state':dep[2] if len(dep)>=3 else None,
            'flags':x['flags'],'flags_hex':x['flags_hex'],
            'descriptor_abs':base+x['descriptor_rel'],'descriptor_size':x['descriptor_size'],
            'map_abs':x['map_offset_abs'],'map_rel':x['map_offset_rel'],'map_size':x['map_size'],
            'deps':dep,
        })
    rows.sort(key=lambda r:999 if r['state'] is None else r['state']); return base,size,hdr,rows

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); dig=hashlib.sha256(d).hexdigest()
    if dig!=EXPECTED_UNPACKED_SHA: raise ValueError(dig)
    for site,target in ((LOOKUP_CALL,LOOKUP),(CSP_CALL,CSP)):
        t,k=branch_target(site,u32(d,site))
        if t!=target or k!='BL': raise ValueError(f'pinned call mismatch {site:#x}')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    wrap=list(md.disasm(d[FUNC:CSP_CALL+4],FUNC)); sw=[i for i in wrap if is_fp_minus8_write(i)]
    lookup=disasm_function(md,d,LOOKUP); debug=disasm_function(md,d,DEBUG_DUMP)
    core_linear=disasm_range(md,d,CORE,0x0178CC90); dbget=disasm_function(md,d,DBGET)
    base,size,hdr,maps=cat42(d)
    gb,gbl,gp,gt=xrefs(d,DBGET)
    L=['# M11-P Category-42 CSP selector/flags trace','',f'- SHA-256: `{dig}`',f'- R2YS base `0x{base:08x}` size `0x{size:x}` header rel `0x{hdr:x}`',f'- CSP wrapper `0x{FUNC:08x}`',f'- lookup wrapper `0x{LOOKUP:08x}`',f'- request debug dumper `0x{DEBUG_DUMP:08x}`',f'- resolver core `0x{CORE:08x}`',f'- DB handle lookup `0x{DBGET:08x}`',f'- CSP setter `0x{CSP:08x}`','']
    L += ['## Category-42 descriptor records','', '| state | flags | descriptor abs | desc bytes | map abs | map rel | map bytes | dependencies |','|---:|---:|---:|---:|---:|---:|---:|---|']
    for m in maps:
        L.append(f"| {m['state']:+d} | `{m['flags_hex']}` | `0x{m['descriptor_abs']:08x}` | {m['descriptor_size']} | `0x{m['map_abs']:08x}` | `0x{m['map_rel']:x}` | {m['map_size']} | `{m['deps']}` |")
    L += ['','## CSP request construction near resolver call','```asm']
    idx=next(i for i,x in enumerate(wrap) if x.address==LOOKUP_CALL)
    L += [fmt(x) for x in wrap[max(0,idx-24):idx+5]]+['```','']
    L += [f'## Lookup wrapper `0x{LOOKUP:08x}`','```asm',*[fmt(x) for x in lookup],'```','']
    L += [f'## Resolver core full linear region `0x{CORE:08x}..0x0178cc90`','```asm',*[fmt(x) for x in core_linear],'```','']
    L += [f'## DB handle lookup `0x{DBGET:08x}`',f'- B xrefs `{len(gb)}`, BL xrefs `{len(gbl)}`, pointer refs `{len(gp)}`, Thumb-pointer refs `{len(gt)}`','```asm',*[fmt(x) for x in dbget],'```','']
    L += ['### DB-handle MOVW/MOVT constants','| insn | reg | value | ASCII if file-like |','|---:|---|---:|---|']
    for ad,r,v in movw_movt(dbget): L.append(f"| `0x{ad:08x}` | {r} | `0x{v:08x}` | {ascii_near(d,v).replace('|','\\|')[:180]} |")
    L += ['',f'## Request debug dumper `0x{DEBUG_DUMP:08x}` (classification correction)','', 'The function is called before resolution but behaves as a log/debug formatter gated by a global verbosity value; it is not treated as database initialization.','```asm',*[fmt(x) for x in debug[:64]],'```','']
    L += ['## Evidence boundary','','If the Category-42 flags select the request fields containing the observed runtime values, the exact dependency-to-request mapping can be stated from primary firmware. The resolver already proves category comparison and returns a base-plus-map-offset pointer on match; the wrapper then copies the 44-byte result verbatim to the CSP setter. None of these software traces establish the internal Milbeaut CSYKY/chroma-reference/piecewise fixed-point pixel equation.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)); print(a.output)
if __name__=='__main__': main()
