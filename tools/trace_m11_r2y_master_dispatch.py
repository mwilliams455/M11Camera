#!/usr/bin/env python3
"""Resolve the Leica M11-P R2Y master parameter dispatcher around 0x0157bb14.

Direct Leica evidence shows this family calls neighboring known R2Y selector
families including CC0 (0x01576894), gamma-invalid (0x01579bf8), and the true
callable gamma-main entry 0x01579338. This pass reconstructs its switch/jump
mechanism, maps case indices to exact case targets, and records the direct
selector call(s) made by each case. The proven code-pointer affine 0x3faa87d0
is used only when table words are absolute translated code pointers.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CODEPTR_BASE=0x3FAA87D0
START=0x0157BB14
END=0x0157BF34
KNOWN={
    0x01576894:'CC0_selector',
    0x01576F0C:'r2y_selector_76f0c',
    0x01576FD0:'r2y_selector_76fd0',
    0x01577054:'r2y_selector_77054',
    0x01579338:'gamma_main_callable',
    0x01579BF8:'gamma_invalid_BB060017',
    0x01579CBC:'gamma_adjacent_79cbc',
    0x0157A138:'r2y_selector_7a138',
}


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    return list(md.disasm(d[s:e],s))
def indexed_pc_load(i):
    if not i.mnemonic.startswith('ldr') or not i.op_str.startswith('pc, [pc,'): return None
    m=re.search(r'\[pc, (r\d+|ip)(?:, lsl #2)?\]',i.op_str)
    return m.group(1) if m else None
def table_for_dispatch(d,insns,idx):
    i=insns[idx];reg=indexed_pc_load(i)
    if not reg:return None
    # ARM PC at execute is address+8; jump table starts immediately after the
    # indexed load for canonical ldr pc,[pc,R,lsl#2].
    table=i.address+8
    # Search backward for nearest CMP of same register against a small imm.
    maxcase=None;cmpaddr=None
    for j in range(idx-1,max(-1,idx-24),-1):
        q=insns[j]
        m=re.fullmatch(rf'{re.escape(reg)}, #(0x[0-9a-f]+|[0-9]+)',q.op_str)
        if q.mnemonic=='cmp' and m:
            maxcase=int(m.group(1),0);cmpaddr=q.address;break
    if maxcase is None or maxcase>0x100:return None
    words=[u32(d,table+4*k) for k in range(maxcase+1)]
    candidates=[]
    # Candidate 1: proven translated absolute pointers.
    mapped=[(w-CODEPTR_BASE)&0xffffffff for w in words]
    if all(START<=x<END and not(x&3) for x in mapped):
        candidates.append(('translated_absolute',mapped))
    # Candidate 2: raw absolute offsets.
    if all(START<=w<END and not(w&3) for w in words):
        candidates.append(('raw_absolute',words))
    return {'site':i.address,'reg':reg,'cmp':cmpaddr,'maxcase':maxcase,'table':table,'words':words,'candidates':candidates}
def case_summary(d,target,all_targets):
    nexts=sorted(x for x in all_targets if x>target)
    bound=min(nexts[0] if nexts else END, target+0x100)
    ins=disasm(d,target,bound)
    calls=[]
    for i in ins:
        bt=bl_target(i.address,u32(d,i.address)) if i.address+4<=len(d) else None
        if bt is not None:calls.append((i.address,bt,KNOWN.get(bt,'')))
        # Most cases end in an unconditional branch to common epilogue.
        if i.mnemonic=='b' and i.address>target:break
        if i.mnemonic.startswith('pop') and 'pc' in i.op_str:break
    return bound,ins,calls
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    ins=disasm(d,START,END)
    dispatch=[]
    for n,i in enumerate(ins):
        if indexed_pc_load(i):
            x=table_for_dispatch(d,ins,n)
            if x:dispatch.append(x)
    lines=['# M11-P R2A master R2Y parameter dispatcher trace','',f'- SHA-256: `{h}`',f'- dispatcher bound: `0x{START:08x}–0x{END:08x}`',f'- proven code-pointer affine: `0x{CODEPTR_BASE:08x}`',f'- indexed PC dispatches found: `{len(dispatch)}`','']
    lines += ['## Full dispatcher disassembly','```text']
    for i in ins:
        note=''
        if i.address+4<=len(d):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:note=f' ; BL=0x{bt:08x} {KNOWN.get(bt,"")}'
        lines.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    lines += ['```','']
    for n,x in enumerate(dispatch,1):
        lines += [f'## Dispatch `{n}` at `0x{x["site"]:08x}`','',f'- index register: `{x["reg"]}`',f'- bound compare: `0x{x["cmp"]:08x}` <= `{x["maxcase"]}`',f'- table raw: `0x{x["table"]:08x}`','- raw words: '+', '.join(f'`0x{w:08x}`' for w in x['words']),f'- viable target encodings: `{len(x["candidates"])}`','']
        for kind,mapped in x['candidates']:
            lines += [f'### `{kind}` case map','']
            uniq=sorted(set(mapped))
            for case,t in enumerate(mapped):
                bound,ci,calls=case_summary(d,t,uniq)
                lines.append(f'#### case `{case}` -> `0x{t:08x}`')
                if calls:
                    for ca,bt,label in calls:lines.append(f'- call `0x{ca:08x}` -> `0x{bt:08x}` {label}'.rstrip())
                else:lines.append('- no direct BL before local case exit')
                lines += ['```text']
                for q in ci[:36]:
                    note=''
                    bt=bl_target(q.address,u32(d,q.address)) if q.address+4<=len(d) else None
                    if bt is not None:note=f' ; BL=0x{bt:08x} {KNOWN.get(bt,"")}'
                    lines.append(f'0x{q.address:08x}: {q.mnemonic} {q.op_str}{note}'.rstrip())
                lines += ['```','']
    lines += ['## Interpretation boundary','', 'Case numbers are reported as switch indices exactly. They are promoted to numbered R2YS categories only if the dispatcher input construction or independent category evidence proves that equivalence. A neighboring function label alone is insufficient.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
