#!/usr/bin/env python3
"""Resolve the Leica M11-P R2Y BB06 master dispatcher around 0x0157bb14.

Direct Leica evidence shows this family calls neighboring known R2Y selector
families including CC0, gamma-invalid, and callable gamma-main 0x01579338.
The dispatcher computes index = incoming_word + 0x44F9FFFF (mod 2^32), so case
N corresponds exactly to incoming BB06 word 0xBB060001 + N for N=0..35.
The proven code-pointer affine 0x3faa87d0 resolves its absolute jump table.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CODEPTR_BASE=0x3FAA87D0
CASE0_COMMAND=0xBB060001
INDEX_BIAS=0x44F9FFFF
START=0x0157BB14
END=0x0157BF34
KNOWN={0x01576894:'CC0_selector',0x01576F0C:'r2y_selector_76f0c',0x01576FD0:'r2y_selector_76fd0',0x01577054:'r2y_selector_77054',0x01579338:'gamma_main_callable',0x01579BF8:'gamma_invalid_BB060017',0x01579CBC:'gamma_adjacent_79cbc',0x0157A138:'r2y_selector_7a138'}

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
    table=i.address+8;maxcase=None;cmpaddr=None
    for j in range(idx-1,max(-1,idx-24),-1):
        q=insns[j];m=re.fullmatch(rf'{re.escape(reg)}, #(0x[0-9a-f]+|[0-9]+)',q.op_str)
        if q.mnemonic=='cmp' and m:maxcase=int(m.group(1),0);cmpaddr=q.address;break
    if maxcase is None or maxcase>0x100:return None
    words=[u32(d,table+4*k) for k in range(maxcase+1)];candidates=[]
    mapped=[(w-CODEPTR_BASE)&0xffffffff for w in words]
    if all(START<=x<END and not(x&3) for x in mapped):candidates.append(('translated_absolute',mapped))
    if all(START<=w<END and not(w&3) for w in words):candidates.append(('raw_absolute',words))
    return {'site':i.address,'reg':reg,'cmp':cmpaddr,'maxcase':maxcase,'table':table,'words':words,'candidates':candidates}
def case_summary(d,target,all_targets):
    nexts=sorted(x for x in all_targets if x>target);bound=min(nexts[0] if nexts else END,target+0x100);ins=disasm(d,target,bound);calls=[]
    for i in ins:
        bt=bl_target(i.address,u32(d,i.address)) if i.address+4<=len(d) else None
        if bt is not None:calls.append((i.address,bt,KNOWN.get(bt,'')))
        if i.mnemonic=='b' and i.address>target:break
        if i.mnemonic.startswith('pop') and 'pc' in i.op_str:break
    return bound,ins,calls
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    # Hard guard for the command-index arithmetic.
    if ((CASE0_COMMAND+INDEX_BIAS)&0xffffffff)!=0:raise ValueError('BB06 index arithmetic invariant failed')
    ins=disasm(d,START,END);dispatch=[]
    # Exact dispatcher guards.
    by={i.address:i for i in ins}
    for a,mn,frag in [(0x0157BB18,'movw','#0xffff'),(0x0157BB1C,'ldr','r3, [r1]'),(0x0157BB20,'movt','#0x44f9'),(0x0157BB2C,'add','r2, r3, r2'),(0x0157BB30,'cmp','r2, #0x23')]:
        i=by.get(a)
        if not i or i.mnemonic!=mn or frag not in i.op_str:raise ValueError(f'dispatch guard failed at {a:#x}')
    for n,i in enumerate(ins):
        if indexed_pc_load(i):
            x=table_for_dispatch(d,ins,n)
            if x:dispatch.append(x)
    lines=['# M11-P R2A master R2Y BB06 dispatcher trace','',f'- SHA-256: `{h}`',f'- dispatcher bound: `0x{START:08x}–0x{END:08x}`',f'- proven code-pointer affine: `0x{CODEPTR_BASE:08x}`',f'- exact index arithmetic: `index = incoming_word + 0x{INDEX_BIAS:08x} (mod 2^32)`',f'- therefore case `N` = incoming `0x{CASE0_COMMAND:08x} + N`; accepted command range `0xBB060001–0xBB060024`.',f'- indexed PC dispatches found: `{len(dispatch)}`','']
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
                incoming=(CASE0_COMMAND+case)&0xffffffff;bound,ci,calls=case_summary(d,t,uniq)
                lines.append(f'#### case `{case}` / incoming `0x{incoming:08x}` -> `0x{t:08x}`')
                if calls:
                    for ca,bt,label in calls:lines.append(f'- call `0x{ca:08x}` -> `0x{bt:08x}` {label}'.rstrip())
                else:lines.append('- no direct BL before local case exit')
                lines += ['```text']
                for q in ci[:36]:
                    note='';bt=bl_target(q.address,u32(d,q.address)) if q.address+4<=len(d) else None
                    if bt is not None:note=f' ; BL=0x{bt:08x} {KNOWN.get(bt,"")}'
                    lines.append(f'0x{q.address:08x}: {q.mnemonic} {q.op_str}{note}'.rstrip())
                lines += ['```','']
    lines += ['## Proven command/handler examples','', '- incoming `BB060014` = case 19 -> callable gamma main `0x01579338`.', '- incoming `BB060016` = case 21 -> gamma-invalid family `0x01579bf8`, which constructs `BB060017`.', '- incoming `BB060018` = case 23 -> CC0 selector `0x01576894`, which constructs `BB060019`.', '', '## Interpretation boundary','', 'These are BB06 command identifiers. They are NOT promoted to numbered R2YS categories; category equivalence requires separate descriptor evidence.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
