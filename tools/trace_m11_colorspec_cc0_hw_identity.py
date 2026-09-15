#!/usr/bin/env python3
from __future__ import annotations
import argparse, bisect, hashlib, struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000; END=0x02000000
GET_FRAME=0x01721858; CM_FINISH=0x016EB09C
R2Y_CTRL=0x01B1CDA4; R2Y_BUILDER=0x0172C19C; R2Y_MCC_WRITER=0x01B2D324
FIELDS={0x1F8:'dynamic_CC0',0x250:'DNG_CM1',0x278:'DNG_CM2',0x2A0:'CM_aux48'}
SPECIAL={GET_FRAME,CM_FINISH,R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER}

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b): s=1<<(b-1); return (v^s)-s
def bl_target(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1: return None
    return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def is_push(w): return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))
def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def immediates(i):
    vals=[]
    for o in i.operands:
        if o.type==ARM_OP_IMM: vals.append(o.imm & 0xffffffff)
        elif o.type==ARM_OP_MEM: vals.append(o.mem.disp & 0xffffffff)
    return vals

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise SystemExit(f'wrong SHA {h}')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    ins=list(md.disasm(d[START:END],START)); idx={x.address:n for n,x in enumerate(ins)}
    pushes=[p for p in range(START,END,4) if is_push(u32(d,p))]
    def fstart(addr):
        j=bisect.bisect_right(pushes,addr)-1
        return pushes[j] if j>=0 else addr&~3
    def fend(fs):
        j=bisect.bisect_right(pushes,fs)
        return pushes[j] if j<len(pushes) else END
    callmap=defaultdict(list); callees=defaultdict(list); hits=defaultdict(list); byfunc=defaultdict(list)
    for i in ins:
        fs=fstart(i.address); byfunc[fs].append(i)
        t=bl_target(i.address,u32(d,i.address))
        if t is not None:
            callmap[t].append(i.address); callees[fs].append((i.address,t))
        vals=immediates(i)
        for off in FIELDS:
            if off in vals: hits[off].append(i.address)
    L=['# M11 dynamic ColorSpec CC0 -> hardware identity trace','',f'- SHA256 `{h}`',
       '- Exact CM copy map from `0x016EB09C`: frame+0x1F8 <- ColorSpec root+0x28 (44-byte dynamic CC0); frame+0x250 <- calibration+0x40 (CM1); frame+0x278 <- calibration+0x70 (CM2); frame+0x2A0 <- root+0x82 (48-byte auxiliary block).','']
    L += ['## CM finish callers','',f'- `0x{CM_FINISH:08X}` callers: `{[hex(x) for x in callmap.get(CM_FINISH,[])]}`','']
    getter_calls=callmap.get(GET_FRAME,[]); getter_funcs=sorted(set(fstart(x) for x in getter_calls))
    L += ['## Frame getter callsites','',f'- GET_FRAME `0x{GET_FRAME:08X}` call count: `{len(getter_calls)}`; containing functions: `{[hex(x) for x in getter_funcs]}`','']
    for off,name in FIELDS.items():
        L += [f'## Exact immediate/displacement hits for frame +0x{off:X} ({name})','',f'- total hits: `{len(hits[off])}`','']
        for ha in hits[off]:
            fs=fstart(ha); n=idx.get(ha); has_get=fs in getter_funcs
            special=[(ca,t) for ca,t in callees.get(fs,[]) if t in SPECIAL]
            L += [f'### hit `0x{ha:08X}` func `0x{fs:08X}` GET_FRAME={has_get} special_calls=`{[(hex(x),hex(t)) for x,t in special]}` direct_callers=`{[hex(x) for x in callmap.get(fs,[])]}`','```asm']
            if n is not None:
                for x in ins[max(0,n-12):min(len(ins),n+18)]: L.append(fmt(x))
            L += ['```','']
    L += ['## Functions that both call GET_FRAME and touch target fields','']
    for fs in getter_funcs:
        touched=[]
        for x in byfunc.get(fs,[]):
            vals=immediates(x)
            for off,name in FIELDS.items():
                if off in vals and name not in touched: touched.append(name)
        if not touched: continue
        specials=[(ca,t) for ca,t in callees.get(fs,[]) if t in SPECIAL]
        L.append(f'- func `0x{fs:08X}` touches `{touched}` special_calls `{[(hex(x),hex(t)) for x,t in specials]}` direct callers `{[hex(x) for x in callmap.get(fs,[])]}`')
    L += ['','## Known R2Y entry callers','']
    for t in (R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER): L.append(f'- `0x{t:08X}` callers `{[hex(x) for x in callmap.get(t,[])]}`')
    for t in (R2Y_CTRL,R2Y_BUILDER,R2Y_MCC_WRITER):
        for ca in callmap.get(t,[]):
            n=idx.get(ca); fs=fstart(ca)
            L += ['',f'### R2Y call `0x{ca:08X}` -> `0x{t:08X}` func `0x{fs:08X}`','```asm']
            if n is not None:
                for x in ins[max(0,n-24):min(len(ins),n+12)]: L.append(fmt(x))
            L += ['```']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
