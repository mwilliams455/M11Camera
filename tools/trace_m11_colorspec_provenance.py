#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from collections import deque
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_REG, ARM_OP_MEM, ARM_REG_PC, ARM_REG_SP, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
START=0x01000000; END=0x02000000
CALLSITE=0x016EB088; DUMP_FN=0x016EB09C
MAPWHITE=0x016EC568; MATRIX_INTERP=0x016ED368
COLOR=0x002C9A98; DELTA=0x3FAA87D0
CM1=[2358,-546,-66,-2488,6300,1785,-403,797,3504]
CM2=[1700,-326,-200,-2354,5409,974,-612,976,2276]
EXTRA=[212,-165,-71,-73,676,85,-27,174,285]

def u32(d,a):
    if a < 0 or a+4 > len(d): return None
    return struct.unpack_from('<I',d,a)[0]
def sx(v,b):
    s=1<<(b-1); return (v^s)-s
def branch_target(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1: return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def ispush(w): return w is not None and (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def callers(code,t):
    out=[]
    for q in range(0,len(code)-3,4):
        if branch_target(START+q, struct.unpack_from('<I',code,q)[0])==t: out.append(START+q)
    return out
def func_start(d,a,window=0x20000):
    p=a&~3
    for x in range(p,max(START,p-window),-4):
        if ispush(u32(d,x)): return x
    return max(START,a-0x1000)
def dis(md,d,lo,hi): return list(md.disasm(d[lo:hi],lo))
def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def ascii_at(d,a,maxn=160):
    if a is None or a<0 or a>=len(d): return None
    b=d[a:min(len(d),a+maxn)]
    m=re.match(rb'[\x20-\x7e]{4,}\x00',b)
    return m.group()[:-1].decode('ascii','replace') if m else None

def pcrel_refs(md,d,ins):
    rows=[]
    for op in ins.operands:
        if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
            la=(ins.address+8+op.mem.disp)&0xffffffff
            val=u32(d,la)
            rows.append((la,val,ascii_at(d,val),ascii_at(d,la)))
    if ins.mnemonic in ('add','sub') and len(ins.operands)>=3 and ins.operands[1].type==ARM_OP_REG and ins.operands[1].reg==ARM_REG_PC and ins.operands[2].type==2:
        imm=ins.operands[2].imm
        aa=(ins.address+8 + (imm if ins.mnemonic=='add' else -imm))&0xffffffff
        rows.append((aa,None,ascii_at(d,aa),None))
    return rows

def writes_reg(ins, reg):
    try:
        _,ww=ins.regs_access()
        return reg in ww
    except Exception:
        return bool(ins.operands and ins.operands[0].type==ARM_OP_REG and ins.operands[0].reg==reg)

def stack_accesses(insns):
    out=[]
    for ins in insns:
        for op in ins.operands:
            if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_SP:
                out.append((ins.address,op.mem.disp,fmt(ins)))
    return out

def callgraph_rows(d,code,targets,depth=2):
    q=deque((t,0) for t in targets); seen=set(); rows=[]
    while q:
        t,dep=q.popleft()
        if (t,dep) in seen: continue
        seen.add((t,dep))
        cs=callers(code,t); rows.append((t,dep,cs))
        if dep<depth:
            for c in cs: q.append((func_start(d,c),dep+1))
    return rows

def hexdump(d,a,n=160):
    out=[]
    for p in range(a,a+n,16):
        chunk=d[p:p+16]
        hx=' '.join(f'{x:02x}' for x in chunk)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in chunk)
        out.append(f'{p:08X}  {hx:<47}  {asc}')
    return out

def exact_sig(d,vals):
    b=b''.join(struct.pack('<i',x) for x in vals); out=[]; p=0
    while True:
        p=d.find(b,p)
        if p<0: return out
        out.append(p);p+=1

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise SystemExit(f'bad sha {h}')
    code=d[START:END]
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    L=['# M11-P ColorSpec provenance trace','',f'- unpacked SHA256: `{h}`',f'- call seam: `0x{CALLSITE:08X} -> 0x{DUMP_FN:08X}`','']

    fs=func_start(d,CALLSITE)
    L += ['## 1. Exact call boundary',f'- containing function start (nearest A32 push/LR): `0x{fs:08X}`',f'- callers of containing function: `{[hex(x) for x in callers(code,fs)]}`','```asm']
    insns=dis(md,d,fs,CALLSITE+4)
    L += [fmt(i) for i in insns]+['```','']
    L += ['### Immediate/PC-relative argument provenance immediately before call','']
    tail=[i for i in insns if i.address>=CALLSITE-0x80]
    for reg,label in ((ARM_REG_R0,'r0'),(ARM_REG_R1,'r1'),(ARM_REG_R2,'r2'),(ARM_REG_R3,'r3')):
        L.append(f'- {label} writers:')
        for i in tail:
            if writes_reg(i,reg):
                refs=pcrel_refs(md,d,i); L.append(f'  - `{fmt(i)}`')
                for la,val,sval,slit in refs:
                    L.append(f'    - PC literal/address `0x{la:08X}` value `{None if val is None else hex(val)}` value_ascii `{sval}` literal_ascii `{slit}`')
    L += ['','### PC-relative references in the boundary function','']
    for i in insns:
        refs=pcrel_refs(md,d,i)
        if refs: L.append(f'- `{fmt(i)}` -> `{[(hex(x), None if v is None else hex(v), s, sl) for x,v,s,sl in refs]}`')
    L += ['','### Stack accesses before the call','']
    for addr,disp,text in stack_accesses(insns):
        if CALLSITE-0x300 <= addr <= CALLSITE: L.append(f'- sp `{disp:+#x}`: `{text}`')

    L += ['','## 2. 0x016EB09C callee prologue and raw-record handling','```asm']
    callee=dis(md,d,DUMP_FN,DUMP_FN+0x160)
    L += [fmt(i) for i in callee]+['```','','### Calls made in first 0x160 bytes','']
    for i in callee:
        t=branch_target(i.address,u32(d,i.address))
        if t is not None: L.append(f'- `{fmt(i)}` -> `0x{t:08X}`')

    L += ['','## 3. Static COLOR132 and candidate decoded pointer context','']
    L += [f'- CM1 occurrences `{[hex(x) for x in exact_sig(d,CM1)]}`',f'- CM2 occurrences `{[hex(x) for x in exact_sig(d,CM2)]}`',f'- EXTRA occurrences `{[hex(x) for x in exact_sig(d,EXTRA)]}`','```text']+hexdump(d,COLOR,160)+['```','']

    targets=[DUMP_FN,MAPWHITE,0x016ECB80,0x016ECBEC,MATRIX_INTERP,0x016EFD34,0x016EEE74]
    L += ['## 4. Selected ColorSpec call graph (direct BL, two levels)','']
    for t,dep,cs in callgraph_rows(d,code,targets,2):
        L.append(f'- depth {dep} target/function `0x{t:08X}` callers `{[hex(x) for x in cs]}` caller-functions `{[hex(func_start(d,x)) for x in cs]}`')

    for t,name,span in ((MAPWHITE,'MapWhiteMatrix candidate',0x650),(0x016ECB80,'interpolation wrapper',0x80),(0x016ECBEC,'ColorSpec orchestration',0x500),(MATRIX_INTERP,'MatrixInterpolate',0x1c0)):
        fs2=func_start(d,t)
        L += ['',f'## 5. {name} @ 0x{t:08X}',f'- nearest function start `0x{fs2:08X}`; direct callers `{[hex(x) for x in callers(code,t)]}`','```asm']
        L += [fmt(i) for i in dis(md,d,t,t+span)]+['```']

    L += ['','## 6. Pointer/immediate probes','']
    vals=[COLOR,COLOR+0x2c,COLOR+0x58,(COLOR+DELTA)&0xffffffff,((COLOR+0x2c)+DELTA)&0xffffffff,((COLOR+0x58)+DELTA)&0xffffffff,0xDC94]
    for v in vals:
        lit=[]; b=struct.pack('<I',v); p=START
        while True:
            p=d.find(b,p,END)
            if p<0: break
            if p%4==0: lit.append(p)
            p+=1
        L.append(f'- value `0x{v:08X}` aligned literals in code: `{[hex(x) for x in lit[:100]]}`')

    L += ['','## 7. Nearby ColorSpec string/data region','```text']+hexdump(d,0x0277BEF0,0x180)+['```','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
