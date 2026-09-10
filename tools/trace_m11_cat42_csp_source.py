#!/usr/bin/env python3
"""Trace Leica Category-42 source selection into the Milbeaut CSP wrapper.

Pinned primary-firmware facts from earlier probes:
  CSP HW register programmer : 0x01b68b80
  sole direct CSP callsite   : 0x01731db0
  CSP wrapper entry          : 0x01731970
  generic selector call      : 0x0178d0a8
  wrapper source slot        : [fp, #-8]
  wrapper local CSP struct   : [fp, #-0x34] (44 bytes)

The wrapper constructs a selector request containing category 0x2a (42), calls
0x0178d0a8, copies the returned record field-for-field into the local CSP
structure, then calls the register programmer. This probe expands the generic
selector itself and its references to determine how it resolves the record.
No renderer behaviour is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_FP, ARM_REG_R11

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

FUNC = 0x01731970
CALL = 0x01731DB0
CSP = 0x01B68B80
LOOKUP = 0x0178D0A8
LOOKUP_CALL = 0x01731B34


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def branch_target(addr: int, w: int):
    cond = (w >> 28) & 0xF
    op = (w >> 24) & 0xF
    if cond == 0xF or op not in (0xA, 0xB):
        return None, None
    imm24 = w & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF, ('BL' if op == 0xB else 'B')


def fmt(ins):
    return f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}".rstrip()


def is_fp_minus8_write(ins) -> bool:
    if not ins.mnemonic.startswith(('str', 'stm')):
        return False
    for op in ins.operands:
        if op.type == ARM_OP_MEM and op.mem.base in (ARM_REG_FP, ARM_REG_R11) and op.mem.disp == -8:
            return True
    return False


def all_xrefs(data: bytes, target: int):
    b, bl, ptr, ptr_thumb = [], [], [], []
    for off in range(0, len(data)-3, 4):
        w = u32(data, off)
        t, kind = branch_target(off, w)
        if t == target:
            (bl if kind == 'BL' else b).append(off)
        if w == target:
            ptr.append(off)
        if w == (target | 1):
            ptr_thumb.append(off)
    return b, bl, ptr, ptr_thumb


def category42(data: bytes):
    base, size, header, ds = parse_r2y(data)
    out=[]
    for d in ds:
        if d.get('category') != 42:
            continue
        deps=d.get('dependencies_s32',[])
        out.append({
            'state': deps[2] if len(deps)>=3 else None,
            'descriptor_rel': d.get('descriptor_rel'),
            'descriptor_abs': base + d.get('descriptor_rel',0),
            'map_offset_abs': d.get('map_offset_abs'),
            'map_offset_rel': d.get('map_offset_rel'),
            'map_size': d.get('map_size'),
            'descriptor_size': d.get('descriptor_size'),
            'dependencies': deps,
        })
    return base,size,header,sorted(out,key=lambda x:999 if x['state'] is None else x['state'])


def disasm_function(md, data: bytes, entry: int, max_len: int = 0x4000):
    insns=list(md.disasm(data[entry:min(len(data),entry+max_len)],entry))
    out=[]
    for ins in insns:
        out.append(ins)
        text=(ins.mnemonic+' '+ins.op_str).lower()
        if len(out)>2 and ((ins.mnemonic=='pop' and 'pc' in ins.op_str.lower()) or text.startswith('bx lr') or (ins.mnemonic.startswith('ldm') and 'pc' in ins.op_str.lower())):
            break
    return out


def ascii_near(data: bytes, value: int):
    if not (0 <= value < len(data)):
        return None
    lo=value
    while lo>0 and value-lo<160 and 32 <= data[lo-1] < 127:
        lo-=1
    hi=value
    while hi<len(data) and hi-value<240 and 32 <= data[hi] < 127:
        hi+=1
    if hi-lo >= 5:
        return data[lo:hi].decode('ascii','replace')
    return None


def movw_movt_constants(insns):
    """Report adjacent same-register MOVW/MOVT absolute constants."""
    rows=[]
    for a,b in zip(insns,insns[1:]):
        if a.mnemonic != 'movw' or b.mnemonic != 'movt':
            continue
        aa=[x.strip() for x in a.op_str.split(',')]
        bb=[x.strip() for x in b.op_str.split(',')]
        if len(aa)!=2 or len(bb)!=2 or aa[0]!=bb[0]:
            continue
        try:
            lo=int(aa[1].replace('#',''),0); hi=int(bb[1].replace('#',''),0)
        except ValueError:
            continue
        rows.append((a.address,aa[0],((hi&0xffff)<<16)|(lo&0xffff)))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('unpacked',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    data=args.unpacked.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked SHA {digest}')
    t,k=branch_target(CALL,u32(data,CALL))
    if t != CSP or k != 'BL': raise ValueError('pinned CSP call no longer valid')
    t,k=branch_target(LOOKUP_CALL,u32(data,LOOKUP_CALL))
    if t != LOOKUP or k != 'BL': raise ValueError('pinned lookup call no longer valid')

    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True
    insns=list(md.disasm(data[FUNC:CALL+4],FUNC))
    slot_writes=[i for i in insns if is_fp_minus8_write(i)]
    wb,wbl,wptr,wpth=all_xrefs(data,FUNC)
    lb,lbl,lptr,lpth=all_xrefs(data,LOOKUP)
    lookup_ins=disasm_function(md,data,LOOKUP)
    r2y_base,r2y_size,r2y_header,maps=category42(data)

    lines=[
        '# M11-P Category-42 CSP source/selector trace','',
        f'- exact unpacked SHA-256: `{digest}`',
        f'- R2YS file base: `0x{r2y_base:08x}` size `0x{r2y_size:x}` header rel `0x{r2y_header:x}`',
        f'- CSP wrapper: `0x{FUNC:08x}`',
        f'- selector: `0x{LOOKUP:08x}`',
        f'- selector callsite in CSP wrapper: `0x{LOOKUP_CALL:08x}`',
        f'- CSP register programmer: `0x{CSP:08x}` via `0x{CALL:08x}`','',
        '## CSP wrapper entry/reference summary','',
        f'- direct B: `{len(wb)}`; BL: `{len(wbl)}`; pointer: `{len(wptr)}`; pointer|1: `{len(wpth)}`',
        f'- writes to `[fp,-8]`: `{len(slot_writes)}`',''
    ]
    for sw in slot_writes:
        idx=next(i for i,x in enumerate(insns) if x.address==sw.address)
        lines += [f'### source-slot write `0x{sw.address:08x}`','', '```asm']
        lines += [fmt(x) for x in insns[max(0,idx-24):min(len(insns),idx+14)]]
        lines += ['```','']

    lines += ['## Category-42 descriptor/map records','',
              '| state | descriptor abs | descriptor size | map abs | map rel | map size | dependencies |',
              '|---:|---:|---:|---:|---:|---:|---|']
    for m in maps:
        st='?' if m['state'] is None else f"{m['state']:+d}"
        lines.append(f"| {st} | `0x{m['descriptor_abs']:08x}` | {m['descriptor_size']} | `0x{m['map_offset_abs']:08x}` | `0x{m['map_offset_rel']:x}` | {m['map_size']} | `{m['dependencies']}` |")

    lines += ['', '## Generic selector xrefs','',
              f'- direct B: `{len(lb)}`', f'- direct BL: `{len(lbl)}`',
              f'- aligned pointer refs: `{len(lptr)}`', f'- aligned pointer|1 refs: `{len(lpth)}`']
    for kind,vals in [('B',lb),('BL',lbl),('PTR',lptr),('PTR_THUMB',lpth)]:
        for x in vals[:128]: lines.append(f'- {kind}: `0x{x:08x}`')

    lines += ['', f'## Generic selector disassembly (`0x{LOOKUP:08x}`)','', '```asm']
    lines += [fmt(x) for x in lookup_ins]
    lines += ['```','']

    lines += ['## Selector MOVW/MOVT constants','', '| instruction | register | value | ASCII if file-address-like |','|---:|---|---:|---|']
    for addr,reg,val in movw_movt_constants(lookup_ins):
        s=ascii_near(data,val)
        if s: s=s.replace('|','\\|')[:180]
        lines.append(f"| `0x{addr:08x}` | {reg} | `0x{val:08x}` | {s or ''} |")

    lines += ['', '## CSP wrapper full pre-call setup','', '```asm']
    lines += [fmt(x) for x in insns]
    lines += ['```','', '## Interpretation boundary','',
              'The immediate selector request contains category 42 before calling the generic selector. The returned pointer is copied field-for-field into the 44-byte CSP control and then programmed into the proven Milbeaut CSP register block. The selector disassembly may establish how that request resolves an R2YS descriptor/map; it still cannot reveal the internal Milbeaut pixel arithmetic for CSYKY/CSYOF/CSYGA/CSYBD.','']
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text('\n'.join(lines))
    print(args.output)

if __name__=='__main__': main()
