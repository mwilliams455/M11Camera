#!/usr/bin/env python3
"""Trace Leica M11-P MCC invocation/source evidence in the canonical firmware.

Evidence gates:
1. Search both static and runtime-relocated pointers for the closed
   Im_R2Y_Ctrl_Multi_Axis entry.
2. Search the same representations for the direct R2Y API targets observed in
   the proven still dispatcher and cluster nearby occurrences. This can expose
   an indirect API table even when no BL exists.
3. Search aligned little-endian 0x78C (the closed public CtrlMultiAxis object
   size) and report bounded word/ASCII context. A size hit is only a lead, not
   accepted as an MCC object without independent structure/provenance.

No renderer changes are made by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict
from pathlib import Path
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

DELTA = 0x3FAA87D0
MCC_API = 0x01B2D324
CTRL_SIZE = 0x78C
STILL_R2Y_TARGETS = [
    0x01B2397C, 0x01B1B9C8, 0x01B1CDA4, 0x01B209D4, 0x01B20BAC,
    0x01B21798, 0x01B24DEC, 0x01B253C0, 0x01B25E0C, 0x01B258A8,
    0x01B21E6C, 0x01B1EA1C,
]
# Known controls, useful for distinguishing a genuine relocated API table from
# coincidental integers.
KNOWN_APIS = {
    MCC_API: 'Im_R2Y_Ctrl_Multi_Axis',
    0x01B624AC: 'closed_YCC_YBLEND_writer',
}
for t in STILL_R2Y_TARGETS:
    KNOWN_APIS.setdefault(t, 'still_dispatch_direct_target')


def hits(data: bytes, value: int, aligned: bool = True):
    needle = struct.pack('<I', value & 0xffffffff)
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        if not aligned or (p & 3) == 0:
            out.append(p)
        p += 1


def ascii_frag(data: bytes, off: int, radius: int = 96):
    lo = max(0, off-radius); hi = min(len(data), off+radius)
    b = data[lo:hi]
    runs = []
    s = None
    for i, x in enumerate(b):
        printable = 0x20 <= x <= 0x7e
        if printable and s is None:
            s = i
        if (not printable or i == len(b)-1) and s is not None:
            e = i if not printable else i+1
            if e-s >= 6:
                runs.append((lo+s, b[s:e].decode('ascii', errors='replace')))
            s = None
    return runs


def words(data: bytes, center: int, before=12, after=12):
    lo = max(0, (center & ~3) - before*4)
    hi = min(len(data), (center & ~3) + (after+1)*4)
    out = []
    for a in range(lo, hi-3, 4):
        v = struct.unpack_from('<I', data, a)[0]
        tag = ''
        if v in KNOWN_APIS:
            tag = f' static:{KNOWN_APIS[v]}'
        else:
            static = (v - DELTA) & 0xffffffff
            if static in KNOWN_APIS:
                tag = f' runtime->{static:#010x}:{KNOWN_APIS[static]}'
            elif 0x01000000 <= static <= 0x02000000:
                tag = f' runtime-code?->{static:#010x}'
        out.append((a, v, tag))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked SHA-256 {digest}')

    lines = [
        '# M11-P 2.6.1 MCC source / relocated API-table trace', '',
        f'- canonical SHA-256: `{digest}`',
        f'- relocation delta: `0x{DELTA:08X}`',
        f'- closed MCC API static: `0x{MCC_API:08X}`',
        f'- closed MCC API runtime: `0x{(MCC_API+DELTA)&0xffffffff:08X}`',
        f'- closed CtrlMultiAxis size: `0x{CTRL_SIZE:X}` ({CTRL_SIZE} bytes)', '',
        '## Exact MCC API pointer search', ''
    ]

    static_hits = hits(data, MCC_API)
    runtime_mcc = (MCC_API + DELTA) & 0xffffffff
    runtime_hits = hits(data, runtime_mcc)
    lines.append(f'- aligned static pointer hits: `{len(static_hits)}`')
    lines.append(f'- aligned runtime-relocated pointer hits: `{len(runtime_hits)}`')
    for label, hs in [('static', static_hits), ('runtime', runtime_hits)]:
        for h in hs[:64]:
            lines += [f'### {label} hit @ `0x{h:08X}`', '', '```text']
            for off, v, tag in words(data, h, 16, 16):
                mark = ' <==' if off == h else ''
                lines.append(f'0x{off:08X}: 0x{v:08X}{tag}{mark}')
            lines += ['```', '']
            frags = ascii_frag(data, h, 128)
            if frags:
                lines.append('Nearby ASCII:')
                for off, text in frags[:12]:
                    lines.append(f'- `0x{off:08X}`: `{text}`')
                lines.append('')

    lines += ['## Relocated-pointer census for still R2Y direct targets', '']
    locs_by_target = {}
    all_runtime_locs = []
    for t in STILL_R2Y_TARGETS:
        rv = (t + DELTA) & 0xffffffff
        hs = hits(data, rv)
        locs_by_target[t] = hs
        all_runtime_locs += [(h,t,rv) for h in hs]
        lines.append(f'- `0x{t:08X}` -> runtime `0x{rv:08X}`: `{len(hs)}` aligned hits' + ((' @ ' + ', '.join(f'`0x{x:08X}`' for x in hs[:12])) if hs else ''))

    lines += ['', '## Relocated API-table clusters', '']
    # Cluster pointer hits whose file offsets lie within 0x400 bytes. A genuine
    # table should contain several known R2Y target pointers close together.
    all_runtime_locs.sort()
    clusters = []
    for h,t,rv in all_runtime_locs:
        placed = False
        for c in clusters:
            if h - c[-1][0] <= 0x400:
                c.append((h,t,rv)); placed=True; break
        if not placed:
            clusters.append([(h,t,rv)])
    clusters = [c for c in clusters if len({x[1] for x in c}) >= 2]
    if not clusters:
        lines.append('- no cluster containing 2+ distinct known still-R2Y API targets')
    for n,c in enumerate(clusters):
        lines += [f'### cluster {n}: `0x{c[0][0]:08X}..0x{c[-1][0]:08X}`', '']
        for h,t,rv in c:
            lines.append(f'- `0x{h:08X}` = runtime `0x{rv:08X}` -> static `0x{t:08X}`')
        lines += ['', 'Context around cluster start:', '', '```text']
        for off,v,tag in words(data, c[0][0], 12, 36):
            lines.append(f'0x{off:08X}: 0x{v:08X}{tag}')
        lines += ['```', '']

    lines += ['## Exact 0x78C size-descriptor search', '']
    size_hits = hits(data, CTRL_SIZE)
    lines.append(f'- aligned `0x0000078C` hits: `{len(size_hits)}`')
    # Report all if modest, otherwise cap but retain total count.
    for h in size_hits[:128]:
        lines += [f'### size hit @ `0x{h:08X}`', '', '```text']
        for off,v,tag in words(data, h, 10, 10):
            mark = ' <==' if off == h else ''
            lines.append(f'0x{off:08X}: 0x{v:08X}{tag}{mark}')
        lines += ['```']
        frags = ascii_frag(data, h, 96)
        if frags:
            lines.append('Nearby ASCII:')
            for off,text in frags[:8]:
                lines.append(f'- `0x{off:08X}`: `{text}`')
        lines.append('')

    lines += [
        '## Gate', '',
        '- A relocated MCC pointer hit inside a coherent R2Y API table would close an indirect invocation route, not the coefficient values by itself.',
        '- A 0x78C integer is only a descriptor lead; it is not accepted as CtrlMultiAxis without source-layout and consumer provenance.',
        '- RENDER1H remains frozen until Leica coefficient/control values are recovered from firmware evidence.', ''
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text('\n'.join(lines) + '\n')
    print(a.output)


if __name__ == '__main__':
    main()
