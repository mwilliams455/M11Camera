#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct, re
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
WRAPPER=0x0178D0A8
RESOLVER=0x0178C89C


def sx(v,b): s=1<<(b-1); return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):
    return [START+q for q in range(0,len(code)-4,4) if bt(START+q,struct.unpack_from('<I',code,q)[0])==t]
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x10000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(struct.unpack_from('<I',code,p)[0]):return START+p
    return max(START,a-0x800)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(x):return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()

def regname(md,r): return md.reg_name(r)

def request_anchor(ins, call_addr, md):
    # Find nearest definition of r0 as fp/sp +/- immediate or mov from such register.
    prior=[x for x in ins if x.address<call_addr and x.id!=0]
    aliases={}
    # walk forward, track registers as (base, signed_disp) for fp/sp based addresses
    r0_anchor=None; why=None
    for x in prior:
        m=x.mnemonic; ops=x.operands
        if m in ('sub','add') and len(ops)>=3 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_REG and ops[2].type==ARM_OP_IMM:
            dst=regname(md,ops[0].reg); src=regname(md,ops[1].reg); imm=ops[2].imm
            if src in ('fp','sp'):
                aliases[dst]=(src, -imm if m=='sub' else imm)
            elif src in aliases:
                b,d=aliases[src]; aliases[dst]=(b,d+(-imm if m=='sub' else imm))
            else: aliases.pop(dst,None)
        elif m=='mov' and len(ops)>=2 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_REG:
            dst=regname(md,ops[0].reg); src=regname(md,ops[1].reg)
            if src in ('fp','sp'): aliases[dst]=(src,0)
            elif src in aliases: aliases[dst]=aliases[src]
            else: aliases.pop(dst,None)
        else:
            # If instruction explicitly writes a tracked register, invalidate unless handled above.
            try:
                _,wr=x.regs_access()
                for rr in wr:
                    n=regname(md,rr)
                    if n in aliases: aliases.pop(n,None)
            except Exception: pass
        if 'r0' in aliases:
            r0_anchor=aliases['r0']; why=fmt(x)
    return r0_anchor,why

def immediate_reg_values(ins, md):
    vals={}
    out=[]
    for x in ins:
        if x.id==0: continue
        ops=x.operands
        if x.mnemonic in ('mov','movw') and len(ops)>=2 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_IMM:
            vals[regname(md,ops[0].reg)]=ops[1].imm & 0xffffffff
        else:
            try:
                _,wr=x.regs_access()
                for rr in wr: vals.pop(regname(md,rr),None)
            except Exception: pass
        # Capture stores and current source constant.
        if x.mnemonic.startswith('str') and len(ops)>=2 and ops[0].type==ARM_OP_REG:
            src=regname(md,ops[0].reg); v=vals.get(src)
            for op in ops[1:]:
                if op.type==ARM_OP_MEM:
                    out.append((x,src,v,regname(md,op.mem.base),op.mem.disp))
    return out

def classify_call(code,md,c):
    e=pro(code,c); ins=dis(md,code,max(e,c-0x700),c+0x10)
    anchor,anchor_why=request_anchor(ins,c,md)
    stores=immediate_reg_values([x for x in ins if x.address<c],md)
    hits=[]
    if anchor:
        base,disp=anchor
        # Direct store to [fp/sp, anchor displacement]. Also store through aliases is left for report.
        for x,src,v,mbase,mdisp in stores:
            if mbase==base and mdisp==disp:
                hits.append((x,v,'direct-anchor'))
    # Pattern fallback: nearest immediate store before request address setup whose address text matches anchor.
    value=None; source=None
    if hits:
        x,v,_=hits[-1]; value=v; source=fmt(x)
    return e,anchor,anchor_why,value,source,ins,stores

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    whole=a.unpacked.read_bytes();h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=whole[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    rows=[]
    for target,label in ((WRAPPER,'wrapper'),(RESOLVER,'resolver-direct')):
        for c in callers(code,target):
            e,anchor,why,v,src,ins,stores=classify_call(code,md,c)
            rows.append((label,c,e,anchor,why,v,src,ins,stores))
    hist=Counter('unknown' if r[5] is None else str(r[5]) for r in rows)
    L=['# M11-P resolver request map-type scan','',f'- SHA: `{h}`','- resolver request `+0x00` = map type (closed by resolver `ldr r0,[request]`)','- SRO map type = `5`','- R2YS map type = `8`',f'- calls scanned: `{len(rows)}`',f'- recovered map-type histogram: `{dict(hist)}`','']
    proven5=[r for r in rows if r[5]==5]
    proven8=[r for r in rows if r[5]==8]
    L += [f'- proven type-5 calls: `{len(proven5)}`',f'- proven type-8 calls: `{len(proven8)}`','']
    for title,subset in (('Proven SRO type-5 calls',proven5),('Positive-control R2YS type-8 calls',proven8[:12]),('Unknown map-type calls',[r for r in rows if r[5] is None])):
        L += [f'## {title}','']
        for label,c,e,anchor,why,v,src,ins,stores in subset:
            L += [f'### {label} call `0x{c:08X}` / function `0x{e:08X}`',f'- request anchor: `{anchor}` via `{why}`',f'- map type: `{v}` via `{src}`','```asm']+[fmt(x) for x in ins[-90:]]+['```','']
    L += ['## All recovered calls','']
    for label,c,e,anchor,why,v,src,ins,stores in rows:
        L += [f'- `{label}` call `0x{c:08X}` func `0x{e:08X}` anchor={anchor} mapType={v} source=`{src}`']
    L += ['','## Interpretation boundary','',
          'Only a store to the exact request start feeding r0 is accepted as a static map type. Values at other request offsets do not count. Unknown calls require interprocedural or dynamic analysis; they are not evidence for SRO.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
