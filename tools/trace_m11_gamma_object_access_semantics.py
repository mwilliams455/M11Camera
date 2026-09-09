#!/usr/bin/env python3
"""Prove Leica M11-P gamma operation-1 mutation vs operation-2 read semantics.

This pass is intentionally exact-address and hash gated. It follows the actual
success paths reached from the gamma operation-1 helper wrappers and checks for
stores into record/payload-derived state. It separately checks the operation-2
helper bodies and success blocks for load-only behavior.

The semantic promotion made by this script is limited to the gamma protocol:
  operation 1 -> write/set path
  operation 2 -> read/get path
It does not assign meaning to operation 3 or to the +0x09 auxiliary field.
"""
from __future__ import annotations

import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'

# Exact success-path spans. End is exclusive.
READ_SPANS=[
    ('op2_major0',0x0169D8FC,0x0169D94C),
    ('op2_major1',0x0169DB1C,0x0169DB90),
    ('op2_major2_data',0x0169E15C,0x0169E19C),
    ('op2_major2_aux',0x0169E2D0,0x0169E360),
]
WRITE_SPANS=[
    ('op1_major0_target',0x0169FC1C,0x0169FCAC),
    ('op1_major1_target',0x0169FF7C,0x0169FFF4),
    ('op1_major2_success',0x016A0900,0x016A09B8),
]

EXPECTED_STORES={
    'op1_major0_target':{
        0x0169FC78:('str','r1, [r2]'),
        0x0169FC88:('str','r2, [r3, #8]'),
    },
    'op1_major1_target':{
        0x0169FFC8:('str','r6, [r2]'),
        0x0169FFD4:('str','r6, [r3, #8]'),
    },
    'op1_major2_success':{
        0x016A099C:('strb','r2, [r1, r3]'),
        0x016A09AC:('strb','r2, [r1, r3]'),
    },
}

# Gamma-exposed operation-1 wrappers and the exact branch/success relation.
WRAPPER_ASSERTS=[
    # 0x0169fcac tail-branches to mutation body 0x0169fc1c.
    (0x0169FCAC,0x0169FCCC,0x0169FC1C),
    # 0x0169fff4 tail-branches to mutation body 0x0169ff7c.
    (0x0169FFF4,0x016A0014,0x0169FF7C),
    # 0x016a08cc reaches its mutation block on successful validation.
    (0x016A08CC,0x016A08F4,0x016A0900),
]


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def b_target(off,w):
    # Any A32 B (including conditional B), not BL.
    if (w & 0x0e000000) != 0x0a000000 or (w & 0x01000000):
        return None
    imm=w&0xffffff
    if imm&0x800000: imm-=0x1000000
    return off+8+(imm<<2)

def insns(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    return list(md.disasm(d[s:e],s))

def imap(d,s,e): return {i.address:i for i in insns(d,s,e)}
def assert_ins(m,a,mn,op):
    i=m.get(a)
    if i is None or i.mnemonic!=mn or i.op_str!=op:
        got='missing' if i is None else f'{i.mnemonic} {i.op_str}'
        raise ValueError(f'{a:#x}: expected {mn} {op}; got {got}')

def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise ValueError(h)

    # Prove the wrappers really route to the analyzed mutation success blocks.
    wrapper_rows=[]
    for entry,site,target in WRAPPER_ASSERTS:
        t=b_target(site,u32(d,site))
        if t!=target:
            raise ValueError(f'wrapper {entry:#x}: branch {site:#x} -> {t}; expected {target:#x}')
        wrapper_rows.append((entry,site,target))

    read_results=[]
    for label,s,e in READ_SPANS:
        ii=insns(d,s,e)
        stores=[i for i in ii if i.mnemonic.startswith('str')]
        if stores:
            raise ValueError(f'{label}: unexpected store(s): '+', '.join(f'{i.address:#x} {i.mnemonic} {i.op_str}' for i in stores))
        loads=[i for i in ii if i.mnemonic.startswith('ldr')]
        if not loads:
            raise ValueError(f'{label}: expected read evidence')
        read_results.append((label,s,e,loads))

    write_results=[]
    for label,s,e in WRITE_SPANS:
        m=imap(d,s,e)
        for a,(mn,op) in EXPECTED_STORES[label].items():
            assert_ins(m,a,mn,op)
        stores=[i for i in m.values() if i.mnemonic.startswith('str')]
        write_results.append((label,s,e,stores))

    lines=[
        '# M11-P R2A gamma operation read/write semantics proof','',
        f'- SHA-256: `{h}`',
        '- result: **gamma operation 1 is the write/set path; gamma operation 2 is the read/get path**',
        '- proof basis: operation-1 wrappers route to record/payload-derived stores; operation-2 accessor success spans contain loads and no stores.','',
        '## Operation-1 wrapper routing','',
    ]
    for entry,site,target in wrapper_rows:
        lines.append(f'- exposed helper `0x{entry:08x}`: branch at `0x{site:08x}` -> mutation/success block `0x{target:08x}`')

    lines += ['', '## Operation 1 — write/set mutation evidence','']
    for label,s,e,stores in write_results:
        lines += [f'### `{label}` `0x{s:08x}–0x{e:08x}`','']
        for i in stores:
            marker=' **required mutation store**' if i.address in EXPECTED_STORES[label] else ''
            lines.append(f'- `0x{i.address:08x}: {i.mnemonic} {i.op_str}`{marker}')
        lines.append('')

    lines += ['## Operation 2 — read/get evidence','']
    for label,s,e,loads in read_results:
        lines += [f'### `{label}` `0x{s:08x}–0x{e:08x}`','', '- stores in analyzed span: `0`', '- representative loads:']
        for i in loads[:16]:
            lines.append(f'  - `0x{i.address:08x}: {i.mnemonic} {i.op_str}`')
        lines.append('')

    lines += [
        '## Interpretation boundary','',
        'This promotes only gamma operation codes 1 and 2. It does not yet name operation 3, the +0x09 halfword, or any particular external object ID. Major-type-2 operation-1 writes are byte-buffer mutations rather than the scalar word stores used by major types 0/1.',''
    ]
    return '\n'.join(lines)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)

if __name__=='__main__': main()
