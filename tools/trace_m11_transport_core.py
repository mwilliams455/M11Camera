#!/usr/bin/env python3
"""Trace Leica M11-P core transport dispatcher 0x0194ac40.

0x0194a5a4 is a generic command wrapper and forwards
(channel, command, packet_ptr, packet_len) to 0x0194ac40. Gamma BB06 packets use
command 0x31. This pass maps the core target body/callees and all direct callers,
with special emphasis on the known 0x0194a638 callsite. Names remain provisional.
"""
from __future__ import annotations

import argparse, hashlib, struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256="28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
TARGET=0x0194AC40
KNOWN_WRAPPER_CALL=0x0194A638
SCAN_START=0x01000000
SCAN_END=0x02000000


def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def bl_target(off,w):
    if (w & 0x0F000000)!=0x0B000000: return None
    imm=w&0xFFFFFF
    if imm&0x800000: imm-=0x1000000
    return off+8+(imm<<2)

def is_prologue(ins): return ins is not None and ins.mnemonic in ('push','stmdb') and 'lr' in ins.op_str and (ins.mnemonic=='push' or 'sp' in ins.op_str)
def nearest_prologue(d,c,r=0x1200):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); best=None
    for o in range(max(SCAN_START,c-r)&~3,c+1,4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i): best=o
    return best
def next_prologue(d,s,max_len=0x2400):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    for o in range(s+4,min(len(d)-4,s+max_len),4):
        i=next(md.disasm(d[o:o+4],o),None)
        if is_prologue(i): return o
    return min(len(d),s+max_len)
def callers(d,t):
    return [o for o in range(SCAN_START,min(SCAN_END,len(d)-4)&~3,4) if bl_target(o,u32(d,o))==t]
def disasm(d,s,e,limit=None):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True; out=[]
    for n,i in enumerate(md.disasm(d[max(0,s):min(len(d),e)],max(0,s))):
        if limit is not None and n>=limit: break
        note=''
        if i.address+4<=len(d) and not(i.address&3):
            bt=bl_target(i.address,u32(d,i.address))
            if bt is not None: note=f' ; BL=0x{bt:08x}'
        out.append(f'0x{i.address:08x}: {i.mnemonic} {i.op_str}{note}'.rstrip())
    return out

def report(d):
    h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_SHA256: raise ValueError(h)
    cs=callers(d,TARGET); start=nearest_prologue(d,TARGET) or TARGET; end=next_prologue(d,start)
    direct=Counter()
    for o in range(start,end,4):
        bt=bl_target(o,u32(d,o))
        if bt is not None: direct[bt]+=1
    lines=['# M11-P R2A core transport dispatcher trace','',f'- SHA-256: `{h}`',f'- target: `0x{TARGET:08x}`',f'- body bound: `0x{start:08x}–0x{end:08x}` (`0x{end-start:x}` bytes)',f'- direct A32 callers: `{len(cs)}`',f'- known generic-wrapper callsite: `0x{KNOWN_WRAPPER_CALL:08x}`','', '## Direct target-body callees','']
    for t,n in direct.most_common(60): lines.append(f'- `0x{t:08x}`: `{n}` call(s)')
    lines += ['', '## Target body','', '```text']; lines.extend(disasm(d,start,end,520)); lines += ['```','', '## Caller windows','']
    for c in cs[:120]:
        p=nearest_prologue(d,c); lines += [f'### call `0x{c:08x}` / prologue `{("0x%08x"%p) if p else "unknown"}`','```text']; lines.extend(disasm(d,max(SCAN_START,c-0x70),c+0x14,44)); lines += ['```','']
    lines += ['## Interpretation boundary','', 'This establishes transport control flow only. A mailbox/IPC/device name is assigned only if downstream register or explicit diagnostic evidence supports it.','']
    return '\n'.join(lines)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)
if __name__=='__main__': main()
