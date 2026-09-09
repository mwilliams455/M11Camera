#!/usr/bin/env python3
"""Trace Leica M11-P producers of the proven incoming gamma command BB060014.

The exact master R2Y dispatcher maps incoming BB060014 to callable gamma main
0x01579338. Gamma then passes request word +0x04 to the generic object lookup
0x0169e7a4, proving that field is an external object ID. This pass finds every
construction/reference of 0xBB060014 in the full image and disassembles the
surrounding producer functions, highlighting stores near packet offsets and
subsequent transport calls.
"""
from __future__ import annotations

import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CMD=0xBB060014
CODE_START=0x01000000
CODE_END=0x02000000


def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w&0x0f000000)!=0x0b000000:return None
    imm=w&0xffffff
    if imm&0x800000:imm-=0x1000000
    return off+8+(imm<<2)
def mov16(w):
    op=w&0x0ff00000
    if op not in (0x03000000,0x03400000):return None
    return ('movw' if op==0x03000000 else 'movt',(w>>12)&0xf,((w>>4)&0xf000)|(w&0xfff))
def is_mov_imm_cmd_low(w):
    # Capstone-based recognition is used below; this helper only exists for raw scan symmetry.
    return False
def is_prologue(i):return i is not None and i.mnemonic in ('push','stmdb') and 'lr' in i.op_str and (i.mnemonic=='push' or 'sp' in i.op_str)
def nearest_prologue(d,c,r=0x1800):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);best=None
    for o in range(max(CODE_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):best=o
    return best
def next_prologue(d,s,maxlen=0x2400):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(CODE_END,len(d)-4,s+maxlen),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i):return o
    return min(CODE_END,len(d),s+maxlen)
def raw_hits(d):
    n=struct.pack('<I',CMD);out=[];p=0
    while True:
        p=d.find(n,p)
        if p<0:break
        if not(p&3):out.append(p)
        p+=1
    return out
def construction_hits(d):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);out=[]
    # Track MOV/MOVW low 0x14 followed shortly by MOVT 0xBB06 in same reg.
    for o in range(CODE_START,min(CODE_END,len(d)-4)&~3,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if not i:continue
        m=re.fullmatch(r'(r\d+|ip|lr), #(0x[0-9a-f]+|[0-9]+)',i.op_str)
        if i.mnemonic not in ('mov','movw') or not m or int(m.group(2),0)!=0x14:continue
        reg=m.group(1)
        for p in range(o+4,min(CODE_END,o+0x30)+1,4):
            j=next(md.disasm(d[p:p+4],p),None)
            if not j:continue
            q=re.fullmatch(rf'{re.escape(reg)}, #(0x[0-9a-f]+|[0-9]+)',j.op_str)
            if j.mnemonic=='movt' and q:
                if int(q.group(1),0)==0xbb06:out.append((o,p,reg))
                break
            # stop on obvious overwrite of same reg
            if j.op_str.startswith(reg+',') and j.mnemonic in ('mov','movw','ldr','add','sub'):break
    return out
def disasm(d,s,e):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True;out=[]
    for i in md.disasm(d[s:e],s):
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None:note=f' ; BL=0x{bt:08x}'
        out.append((i,f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip()))
    return out
def packet_store_signals(rows):
    sig=[]
    for i,text in rows:
        if i.mnemonic.startswith('str') and ('#4]' in i.op_str or '#8]' in i.op_str or '#0xc]' in i.op_str or '#0x10]' in i.op_str or '[sp' in i.op_str):sig.append(text)
        if i.mnemonic in ('mov','movw','movt') and any(x in i.op_str for x in ('#0x14','#0xbb06','#0xf9','#0x109','#0x110','#0x10c')):sig.append(text)
    return sig
def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256:raise ValueError(h)
    ch=construction_hits(d);rh=raw_hits(d)
    allsites=sorted(set([a for a,_,_ in ch]+rh))
    lines=['# M11-P R2A BB060014 gamma request producer trace','',f'- SHA-256: `{h}`',f'- proven incoming gamma command: `0x{CMD:08x}`',f'- MOV/MOVW+MOVT constructions: `{len(ch)}`',f'- raw aligned command words: `{len(rh)}`',f'- distinct sites: `{len(allsites)}`','']
    for n,site in enumerate(allsites,1):
        pro=nearest_prologue(d,site);end=next_prologue(d,pro) if pro else min(len(d),site+0x400);rows=disasm(d,pro or max(CODE_START,site-0x100),end)
        lines += [f'## site `{n}` at `0x{site:08x}`','',f'- nearest prologue: `{("0x%08x"%pro) if pro else "unknown"}`',f'- bound: `0x{end:08x}`']
        pairs=[x for x in ch if x[0]==site]
        for a,b,r in pairs:lines.append(f'- constructed in `{r}` by `0x{a:08x}` + MOVT `0x{b:08x}`')
        if site in rh:lines.append('- exact raw 32-bit word occurrence')
        lines += ['- packet/store signals:']
        for x in packet_store_signals(rows)[:160]:lines.append(f'  - `{x}`')
        lines += ['','```text'];lines.extend(text for _,text in rows[:700]);lines += ['```','']
    lines += ['## Interpretation boundary','', 'A BB060014 constant only identifies a gamma request producer when surrounding code actually places it in a request buffer or invokes a transport/send path. Object ID semantics are promoted only when the +0x04 field can be traced to a constant or caller argument and then joined to the exact generated object table.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(report(a.unpacked.read_bytes()));print(a.output)
if __name__=='__main__':main()
