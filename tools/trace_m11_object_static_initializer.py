#!/usr/bin/env python3
"""Decode the generated Leica M11-P 0x30-byte object-table initializer.

0x016a4178 is directly called once by the object-table installer. It emits a
large straight-line sequence of constant stores into base 0x434295e0. This pass
symbolically tracks simple A32 constant construction and store addresses to
recover the generated records, rather than misclassifying the routine as a
heap allocator.

The decoder is intentionally narrow: it understands only constant MOV/MOVW/
MOVT/MVN/ADD/SUB and STR/STRB/STRH forms needed for the generated initializer.
No execution of firmware is attempted.
"""
from __future__ import annotations

import argparse, hashlib, re
from collections import Counter, defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
START=0x016A4178
MAX_END=0x016D4000
TABLE_BASE=0x434295E0
RECORD_SIZE=0x30
MAX_RECORDS=0x210


def regnum(name):
    if name=='ip': return 12
    if name=='fp': return 11
    if name=='sp': return 13
    if name=='lr': return 14
    if name=='pc': return 15
    if name.startswith('r') and name[1:].isdigit():return int(name[1:])
    return None
def imm(s):
    s=s.strip()
    if not s.startswith('#'):return None
    try:return int(s[1:],0)&0xffffffff
    except:return None
def split2(op):
    a=op.split(',',1)
    return (a[0].strip(),a[1].strip()) if len(a)==2 else (None,None)
def disasm(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    return list(md.disasm(d[START:min(len(d),MAX_END)],START))
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    ins=disasm(d);regs={};stores=[];ret=None
    for i in ins:
        m=i.mnemonic;op=i.op_str
        if i.address>START+0x800 and ((m=='bx' and op.strip()=='lr') or (m.startswith('pop') and 'pc' in op)):
            ret=i.address;break
        if m=='movw':
            rd,x=split2(op);r=regnum(rd);v=imm(x)
            # ARM MOVW writes a zero-extended 16-bit immediate; it does NOT
            # preserve a prior high half. MOVT is the operation that preserves
            # the low half while replacing bits 31:16.
            if r is not None and v is not None:regs[r]=v&0xffff
            continue
        if m=='movt':
            rd,x=split2(op);r=regnum(rd);v=imm(x)
            if r is not None and v is not None:regs[r]=(regs.get(r,0)&0xffff)|((v&0xffff)<<16)
            continue
        if m=='mov':
            rd,x=split2(op);r=regnum(rd)
            if r is not None:
                v=imm(x)
                if v is not None:regs[r]=v
                else:
                    rr=regnum(x);regs[r]=regs.get(rr) if rr is not None and rr in regs else None
            continue
        if m=='mvn':
            rd,x=split2(op);r=regnum(rd);v=imm(x)
            if r is not None:regs[r]=((~v)&0xffffffff) if v is not None else None
            continue
        if m in ('add','sub'):
            parts=[x.strip() for x in op.split(',')]
            if len(parts)==3:
                rd,rn,x=parts;dreg=regnum(rd);nreg=regnum(rn);v=imm(x)
                if dreg is not None:
                    if nreg is not None and nreg in regs and regs[nreg] is not None and v is not None:
                        regs[dreg]=(regs[nreg]+v if m=='add' else regs[nreg]-v)&0xffffffff
                    else: regs[dreg]=None
            continue
        if m in ('str','strb','strh'):
            mm=re.fullmatch(r'(r\d+|ip|fp|lr), \[(r\d+|ip|fp|sp|lr)(?:, #(0x[0-9a-f]+|[0-9]+))?\]',op)
            if mm:
                sr,br,ofs=mm.groups();sreg=regnum(sr);breg=regnum(br);off=int(ofs,0) if ofs else 0
                base=regs.get(breg);val=regs.get(sreg)
                if base is not None:
                    addr=(base+off)&0xffffffff
                    if TABLE_BASE<=addr<TABLE_BASE+RECORD_SIZE*MAX_RECORDS:
                        width={'strb':1,'strh':2,'str':4}[m]
                        if val is not None: val &= (1<<(width*8))-1
                        stores.append((i.address,addr,width,val,op))
            continue

    records=defaultdict(dict);sources=defaultdict(list)
    for ia,addr,w,val,op in stores:
        idx=(addr-TABLE_BASE)//RECORD_SIZE;fo=(addr-TABLE_BASE)%RECORD_SIZE
        records[idx][fo]=(w,val);sources[idx].append((ia,fo,w,val,op))
    def field(idx,off):
        x=records.get(idx,{}).get(off)
        return x[1] if x else None
    subtypes=Counter();majors=Counter();ids=[]
    for idx in sorted(records):
        st=field(idx,2);mt=field(idx,0);eid=field(idx,8);pp=field(idx,0x2c)
        if st is not None:subtypes[st]+=1
        if mt is not None:majors[mt]+=1
        if eid is not None:ids.append((idx,eid,mt,st,pp))
    complete=sum(1 for idx in records if field(idx,0) is not None and field(idx,2) is not None and field(idx,8) is not None and field(idx,0x2c) is not None)
    lines=['# M11-P R2A generated object-table initializer decode','',f'- SHA-256: `{h}`',f'- initializer entry: `0x{START:08x}`',f'- first return found: `{("0x%08x"%ret) if ret else "not found before scan bound"}`',f'- fixed generated table base: `0x{TABLE_BASE:08x}`',f'- record size: `0x{RECORD_SIZE:x}`; accessor capacity: `0x{MAX_RECORDS:x}` records',f'- constant stores decoded into table: `{len(stores)}`',f'- distinct record indices touched: `{len(records)}`',f'- records with major/subtype/external-id/payload all decoded: `{complete}`',f'- highest record index touched: `{max(records) if records else -1}`','', '## Field distributions','', '- major type (+0x00): '+', '.join(f'`{k}`: `{v}`' for k,v in sorted(majors.items())), '- subtype (+0x02): '+', '.join(f'`0x{k:04x}`: `{v}`' for k,v in sorted(subtypes.items())), '', '## Records with external IDs','', '| idx | major | subtype | external ID (+0x08) | payload (+0x2c) |', '|---:|---:|---:|---:|---:|']
    for idx,eid,mt,st,pp in ids:
        lines.append(f'| {idx} | {"" if mt is None else mt} | {"" if st is None else f"0x{st:04x}"} | `0x{eid:08x}` | {"" if pp is None else f"`0x{pp:08x}`"} |')
    lines += ['', '## Exact decoded writes by record','']
    for idx in sorted(records):
        mt=field(idx,0);st=field(idx,2);eid=field(idx,8);pp=field(idx,0x2c)
        lines.append(f'### record `{idx}` @ `0x{TABLE_BASE+idx*RECORD_SIZE:08x}` — major `{mt}`, subtype `{("0x%04x"%st) if st is not None else "?"}`, external `{("0x%08x"%eid) if eid is not None else "?"}`, payload `{("0x%08x"%pp) if pp is not None else "?"}`')
        for ia,fo,w,val,op in sources[idx]:
            lines.append(f'- `0x{ia:08x}` field `+0x{fo:02x}` width `{w}` value `{("0x%08x"%val) if val is not None else "unknown"}` (`{op}`)')
        lines.append('')
    lines += ['## Interpretation boundary','', 'This proves constant initialization only for fields written by the straight-line generator. Missing vector/dynamic fields are not assumed to be zero. A subtype value 0xffff is outside the scalar 1..6 enum and is kept as a separate non-scalar sentinel/class marker.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
