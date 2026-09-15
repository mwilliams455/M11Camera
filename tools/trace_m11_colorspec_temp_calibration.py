#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
RANGES=[
 ('XY_TEMP_CORE',0x016EFC80,0x016F0600),
 ('CAL_CONFIG_FILL',0x016E9EDC,0x016EAC00),
 ('CAL_BIN_LOADER',0x016E9678,0x016E9EDC),
 ('CAL_INIT',0x016EAF60,0x016EB060),
]
TEMP_TABLE_RUNTIME=0x42224B38
RUNTIME_DELTA=0x3FAA87D0

def fmt(i): return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()

def pc_literal(i,d):
    if i.mnemonic not in ('vldr','ldr') or '[pc' not in i.op_str: return None
    m=re.search(r'\[pc(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\]',i.op_str)
    if not m: return None
    disp=int(m.group(1),0) if m.group(1) else 0
    addr=((i.address+8)&~3)+disp
    if i.mnemonic=='vldr' and i.op_str.strip().startswith('d') and 0<=addr<=len(d)-8:
        raw=d[addr:addr+8]
        return addr,raw.hex(),struct.unpack('<d',raw)[0]
    if 0<=addr<=len(d)-4:
        raw=d[addr:addr+4]
        return addr,raw.hex(),struct.unpack('<I',raw)[0]
    return None

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED: raise SystemExit(h)
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.skipdata=True
    L=['# M11 ColorSpec temperature / calibration trace','',f'- SHA256 `{h}`','',
       '- Goal: close xy->temperature/tint arithmetic and Q-format calibration matrix conversion used by dynamic CC0.','']
    for name,lo,hi in RANGES:
        ins=list(md.disasm(d[lo:hi],lo))
        L += [f'## {name} `{lo:#010x}`..`{hi:#010x}`','```asm']+[fmt(i) for i in ins]+['```','']
        lits=[]
        for i in ins:
            x=pc_literal(i,d)
            if x: lits.append((i.address,)+x)
        if lits:
            L += ['### PC-relative literals','']
            for ia,addr,raw,val in lits:
                L.append(f'- instr `{ia:#010x}` -> `{addr:#010x}` raw `{raw}` value `{val!r}`')
            L += ['']

    # Robertson/Wyszecki-Stiles table: 31 entries x 4 doubles, 32-byte stride.
    table_off=TEMP_TABLE_RUNTIME-RUNTIME_DELTA
    L += ['## Firmware temperature table','',
          f'- runtime `{TEMP_TABLE_RUNTIME:#010x}` -> file `{table_off:#010x}`',
          '- layout: 31 rows of four doubles `(r, u, v, t)`','']
    for idx in range(31):
        row=struct.unpack_from('<4d',d,table_off+idx*32)
        L.append(f'- {idx:02d}: `{row[0]:.12g}, {row[1]:.12g}, {row[2]:.12g}, {row[3]:.12g}`')
    L += ['']

    # Exact static COLOR132 payload for side-by-side arithmetic checks.
    off=0x002C9A98
    vals=struct.unpack_from('<33i',d,off)
    L += ['## Static COLOR132 / R2Y_CC0_CM payload','',f'- file offset `{off:#010x}`','']
    for n in range(3):
        rec=vals[n*11:(n+1)*11]
        L.append(f'- record {n+1}: `{list(rec)}`')
    L += ['']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
