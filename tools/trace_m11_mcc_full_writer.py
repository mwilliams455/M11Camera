#!/usr/bin/env python3
"""Close the full Leica M11-P F_R2Y.MCC hardware writer.

Pinned by the hardware-signature scan:
  candidate entry = 0x01B2D324
  public MCC bank = perPipeBase + 0x1000

This trace deliberately ignores the optional Cat27..40 resolver hooks. It walks
one pinned routine far enough to its real return, then proves which public MCC
register families are written. It also records the source halfword/byte offsets
used near each hardware write so the upstream CtrlMultiAxis-like object can be
reconstructed in a follow-up trace.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
ENTRY = 0x01B2D324
MAX_END = 0x01B70000

LANDMARKS = {
    0x000: "MCYC", 0x020: "MCB1AB", 0x024: "MCB1CD", 0x028: "MCB2AB", 0x02C: "MCB2CD",
    0x030: "MCB3AB", 0x034: "MCB3CD", 0x038: "MCB4AB", 0x03C: "MCB4CD",
    0x040: "MCID1", 0x044: "MCID2", 0x048: "MCID3", 0x04C: "MCID4",
    0x080: "MCKA", 0x100: "MCKB", 0x180: "MCKC", 0x200: "MCKD", 0x280: "MCKE", 0x300: "MCKF",
    0x380: "MCKG", 0x400: "MCKH", 0x480: "MCKI", 0x500: "MCKJ", 0x580: "MCKK", 0x600: "MCKL",
    0x680: "MCLA", 0x6C0: "MCLB", 0x700: "MCLC", 0x740: "MCLD", 0x780: "MCLE", 0x7C0: "MCLF",
    0x800: "MCLG", 0x840: "MCLH", 0x880: "MCLI", 0x8C0: "MCLJ", 0x900: "MCLK", 0x940: "MCLL",
    0x980: "MCYCBALP", 0x988: "MCYCBGA", 0x990: "MCYCBBD", 0x9A0: "MCBABALP", 0x9A8: "MCBABOF",
    0x9B0: "MCBABGA", 0x9B8: "MCBABBD",
}

RANGES = [
    (0x000,0x014,"MCYC"), (0x020,0x040,"MCB"), (0x040,0x050,"MCID"),
    (0x080,0x0E4,"MCKA"), (0x100,0x164,"MCKB"), (0x180,0x1E4,"MCKC"), (0x200,0x264,"MCKD"),
    (0x280,0x2E4,"MCKE"), (0x300,0x364,"MCKF"), (0x380,0x3E4,"MCKG"), (0x400,0x464,"MCKH"),
    (0x480,0x4E4,"MCKI"), (0x500,0x564,"MCKJ"), (0x580,0x5E4,"MCKK"), (0x600,0x664,"MCKL"),
    (0x680,0x6BC,"MCLA"), (0x6C0,0x6FC,"MCLB"), (0x700,0x73C,"MCLC"), (0x740,0x77C,"MCLD"),
    (0x780,0x7BC,"MCLE"), (0x7C0,0x7FC,"MCLF"), (0x800,0x83C,"MCLG"), (0x840,0x87C,"MCLH"),
    (0x880,0x8BC,"MCLI"), (0x8C0,0x8FC,"MCLJ"), (0x900,0x93C,"MCLK"), (0x940,0x97C,"MCLL"),
    (0x980,0x9C0,"BLEND"),
]


def u32(d,p): return struct.unpack_from('<I',d,p)[0]

def is_return(w):
    return ((w & 0xFFFF0000) == 0xE8BD0000 and bool(w & 0x8000)) or w == 0xE12FFF1E

def md():
    c=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); c.skipdata=True; return c

def find_end(d):
    for p in range(ENTRY+4, min(MAX_END,len(d)), 4):
        if is_return(u32(d,p)):
            return p+4
    raise RuntimeError('no return before MAX_END')

def mem_disp(op):
    m=re.search(r'\[([^,\]]+)(?:,\s*#(0x[0-9a-f]+|[0-9]+))?\]',op)
    if not m: return None
    return m.group(1).strip(), int(m.group(2),0) if m.group(2) else 0

def family(off):
    for lo,hi,n in RANGES:
        if lo <= off < hi: return n
    return None

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
    if h != EXPECTED_SHA: raise ValueError(h)
    end=find_end(d)
    ins=list(md().disasm(d[ENTRY:end],ENTRY))

    # Hardware stores are recognized structurally: a per-pipe register pointer is
    # repeatedly moved into r2 then advanced by #0x1000; subsequent r2 stores are
    # MCC writes until r2 is overwritten. This routine is compiler-unrolled, so
    # the pattern repeats for nearly every packed register word.
    r2_mcc=False
    stores=[]; all_source=[]; bank_selects=[]
    recent=[]
    for x in ins:
        recent.append(x); recent=recent[-20:]
        if x.mnemonic == 'add' and x.op_str.startswith('r2, r2, #0x1000'):
            r2_mcc=True; bank_selects.append(x.address); continue
        # Explicit writes to r2 that are not the +0x1000 bank select invalidate it.
        if re.match(r'^(mov|movw|movt|ldr|add|sub)\s+r2\b', f'{x.mnemonic} {x.op_str}') and not (x.mnemonic=='add' and x.op_str.startswith('r2, r2, #0x1000')):
            r2_mcc=False
        if r2_mcc and x.mnemonic.startswith('str'):
            mm=mem_disp(x.op_str)
            if mm and mm[0]=='r2' and 0 <= mm[1] < 0xA00:
                off=mm[1]; fam=family(off)
                # Source-access context: retain loads from the local fp-based
                # control/scratch object in the preceding 16 instructions.
                src=[]
                for y in recent[:-1]:
                    if y.mnemonic.startswith('ldr'):
                        sm=mem_disp(y.op_str)
                        if sm and sm[0] in ('r3','fp','r11'):
                            src.append((y.address,y.mnemonic,y.op_str,sm[1]))
                stores.append((x.address,x.mnemonic,x.op_str,off,fam,src[-5:]))

    byfam=defaultdict(list)
    for row in stores:
        byfam[row[4]].append(row)
    expected=[x[2] for x in RANGES]
    covered=[n for n in expected if byfam.get(n)]
    missing=[n for n in expected if not byfam.get(n)]

    # Direct-call xrefs to the exact entry within the normal Leica code region.
    callers=[]
    for p in range(0x01000000, min(0x02000000,len(d))-4,4):
        w=u32(d,p)
        if ((w>>25)&7)==5 and ((w>>24)&1)==1 and ((w>>28)&0xF)!=0xF:
            imm=w & 0xFFFFFF
            if imm & 0x800000: imm-=1<<24
            tgt=(p+8+(imm<<2)) & 0xFFFFFFFF
            if tgt==ENTRY: callers.append(p)

    lines=[
      '# M11-P full MCC writer closure trace','',
      f'- unpacked SHA-256: `{h}`', f'- entry: `0x{ENTRY:08x}`', f'- first architectural return: `0x{end:08x}`',
      f'- function bytes: `{end-ENTRY}` (`0x{end-ENTRY:x}`)', f'- +0x1000 MCC bank selections: `{len(bank_selects)}`',
      f'- recognized MCC stores: `{len(stores)}`', f'- direct callers of exact entry: `{[hex(x) for x in callers]}`','',
      '## Family coverage','', '| family | stores | first | last |', '| --- | ---: | --- | --- |'
    ]
    for n in expected:
        rr=byfam.get(n,[])
        lines.append(f"| {n} | {len(rr)} | {('`0x%08x`'%rr[0][0]) if rr else '-'} | {('`0x%08x`'%rr[-1][0]) if rr else '-'} |")
    lines += ['',f'- covered: `{covered}`',f'- missing: `{missing}`','', '## Landmark stores','']
    for off,name in LANDMARKS.items():
        rr=[r for r in stores if r[3]==off]
        lines.append(f"### {name} +0x{off:03x}")
        if not rr: lines += ['','No recognized store.','']; continue
        lines += ['']
        for r in rr[:12]:
            lines.append(f"- `0x{r[0]:08x}` `{r[1]} {r[2]}` source-context `{[(hex(s[0]),s[1],s[2]) for s in r[5]]}`")
        lines += ['']
    lines += ['## First/last MCC stores','', '```asm']
    for r in stores[:24]+stores[-24:]: lines.append(f"0x{r[0]:08x}: {r[1]} {r[2]} ; {r[4]} +0x{r[3]:03x}")
    lines += ['```','', '## Closure criterion','',
              'Hardware-writer identity is closed only if MCYC/MCB/MCID, all MCKA-L, all MCLA-L, and the blend tail are all present in this single routine. Missing families remain an open boundary.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)

if __name__=='__main__': main()
