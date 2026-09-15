#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
ROOT=0x43430188
RANGES=[
 ('PREP',0x016EBE14,0x016EC0C0),
 ('EXTREMA_A',0x016EDFE4,0x016EE13C),
 ('EXTREMA_B',0x016EE13C,0x016EE294),
 ('MATRIX_HELPER',0x016EE294,0x016EE5B4),
 ('QUANTIZE_3X3',0x016F1CB8,0x016F1FB4),
 ('CHOOSE_SHIFT',0x016F1FB4,0x016F2108),
 ('COLORSPEC_MAIN',0x016F2108,0x016F2C84),
 ('PROCESS_WRAPPER',0x016F2C84,0x016F2CA4),
]
BRADFORD=[0.8951,0.2664,-0.1614,-0.7502,1.7135,0.0367,0.0389,-0.0685,1.0296]
OTHER=[0.1,10.0,0.001,1.0,0.3457,0.3585,5000.0]

def u32(d,a): return struct.unpack_from('<I',d,a)[0] if 0<=a<=len(d)-4 else None
def sx(v,b): s=1<<(b-1); return (v^s)-s
def bl_target(a,w):
    if w is None or ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+(sx(w&0xffffff,24)<<2))&0xffffffff
def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def pc_literal(i,d):
    if i.mnemonic not in ('vldr','ldr') or '[pc' not in i.op_str:return None
    m=re.search(r'\[pc(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\]',i.op_str)
    if not m:return None
    disp=int(m.group(1),0) if m.group(1) else 0
    addr=((i.address+8)&~3)+disp
    if not (0<=addr<len(d)):return None
    if i.mnemonic=='vldr' and i.op_str.strip().startswith('d') and addr+8<=len(d):
        raw=d[addr:addr+8]; return addr,raw.hex(),struct.unpack('<d',raw)[0]
    if addr+4<=len(d):
        raw=d[addr:addr+4]; return addr,raw.hex(),struct.unpack('<I',raw)[0]
    return None
def find_const(d,v,fmtc):
    raw=struct.pack(fmtc,v); out=[]; p=0
    while True:
        p=d.find(raw,p)
        if p<0:break
        out.append(p);p+=1
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED:raise SystemExit(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.skipdata=True
    L=['# M11 ColorSpec CC0 formula — focused trace','',f'- SHA256 `{h}`',f'- root `{ROOT:#010x}`','']

    L += ['## Firmware constant fingerprints','',
          'Searches are byte-exact IEEE-754 little-endian; presence alone is not semantic proof, but clustered addresses are strong compiler/source fingerprints.','']
    for label,vals in [('Bradford',BRADFORD),('Other DNG ColorSpec',OTHER)]:
        L += [f'### {label}']
        for v in vals:
            ds=find_const(d,v,'<d'); fs=find_const(d,v,'<f')
            L.append(f'- `{v}` double `{[hex(x) for x in ds[:32]]}` float `{[hex(x) for x in fs[:32]]}`')
        L += ['']

    # Exact bodies and all PC-relative literals.
    for name,lo,hi in RANGES:
        ins=list(md.disasm(d[lo:hi],lo))
        L += [f'## {name} `{lo:#010x}`..`{hi:#010x}`','```asm']+[fmt(i) for i in ins]+['```','']
        lits=[]
        for i in ins:
            x=pc_literal(i,d)
            if x:lits.append((i.address,)+x)
        if lits:
            L += ['### PC-relative literals','']
            for ia,addr,raw,val in lits:L.append(f'- instr `{ia:#010x}` -> `{addr:#010x}` raw `{raw}` value `{val!r}`')
            L += ['']
        calls=[]
        for i in ins:
            t=bl_target(i.address,u32(d,i.address))
            if t is not None:calls.append((i.address,t))
        if calls:L += ['### direct BL calls',f'- `{[(hex(x),hex(t)) for x,t in calls]}`','']

    # Main callsite windows make dataflow readable without manually scanning the full body.
    mainlo,mainhi=0x016F2108,0x016F2C84
    ins=list(md.disasm(d[mainlo:mainhi],mainlo));idx={x.address:n for n,x in enumerate(ins)}
    interesting={0x016F1CB8:'quantize',0x016F1FB4:'choose_shift',0x016ED060:'matrix_path_A',0x016ECBEC:'matrix_path_B',0x016ED8E0:'copy_matrix',0x016EDA24:'matrix_op',0x016ED644:'matrix_op',0x016ED728:'matrix_op',0x016F0998:'matrix_path_C'}
    L += ['## Main ColorSpec callsite dataflow windows','']
    for i in ins:
        t=bl_target(i.address,u32(d,i.address))
        if t not in interesting:continue
        n=idx[i.address]
        L += [f'### `{i.address:#010x}` -> `{t:#010x}` ({interesting[t]})','```asm']+[fmt(x) for x in ins[max(0,n-18):min(len(ins),n+10)]]+['```','']

    # Explicit stores/copies into ColorSpec root CC records.
    L += ['## Main writes/copies to ColorSpec result regions','']
    for i in ins:
        if i.mnemonic.startswith(('str','vstr')) or i.mnemonic in ('blx',):
            if any(s in i.op_str for s in ('#0x28','#0x54','#0x82','#0xb8')) or 0x016F2780<=i.address<=0x016F2850:
                n=idx[i.address]
                L += [f'### site `{i.address:#010x}`','```asm']+[fmt(x) for x in ins[max(0,n-10):min(len(ins),n+12)]]+['```','']

    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
