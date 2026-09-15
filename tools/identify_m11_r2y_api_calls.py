#!/usr/bin/env python3
"""Identify the Milbeaut R2Y API calls used by the M11-P still dispatcher.

For each direct 0x01Bxxxxx call target already proven in the still R2Y dispatcher,
scan the function prologue region for MOVW/MOVT-constructed Leica runtime string
addresses.  The exact 0x3FAA87D0 relocation delta is independently closed from
the Multi-Axis assertion strings, so runtime string pointers can be mapped back
to the canonical unpacked image and decoded without guessing API names.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

DELTA = 0x3FAA87D0
TARGETS = [
    0x01B2397C, 0x01B1B9C8, 0x01B1CDA4, 0x01B209D4, 0x01B20BAC,
    0x01B21798, 0x01B24DEC, 0x01B253C0, 0x01B25E0C, 0x01B258A8,
    0x01B21E6C, 0x01B1EA1C,
    0x01B2D324,  # closed Multi-Axis writer, positive-control identity
    0x01B624AC,  # closed YCC/YBLEND writer, positive-control identity
]
SCAN = 0x1400


def md():
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    return c


def ascii_z(data: bytes, off: int, cap: int = 180) -> str | None:
    if not (0 <= off < len(data)):
        return None
    end = data.find(b'\x00', off, min(len(data), off + cap))
    if end < 0 or end - off < 6:
        return None
    raw = data[off:end]
    if any((b < 0x20 or b > 0x7e) and b not in (9,) for b in raw):
        return None
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        return None


def imm(i):
    m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', i.op_str)
    return int(m.group(1), 0) if m else None


def dst_reg(i):
    return i.op_str.split(',', 1)[0].strip().lower() if i.op_str else ''


def refs_for_target(c, data: bytes, target: int):
    lows = {}
    refs = []
    for i in c.disasm(data[target:min(len(data), target + SCAN)], target):
        m = i.mnemonic.lower()
        reg = dst_reg(i)
        v = imm(i)
        if m == 'movw' and v is not None:
            lows[reg] = (v & 0xffff, i.address)
        elif m == 'movt' and v is not None and reg in lows:
            lo, lo_at = lows[reg]
            runtime = ((v & 0xffff) << 16) | lo
            static = (runtime - DELTA) & 0xffffffff
            text = ascii_z(data, static)
            if text and ('R2Y' in text or 'r2y' in text or 'Im_' in text or 'error' in text.lower()):
                refs.append((lo_at, i.address, runtime, static, text))
    return refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected unpacked SHA-256 {digest}')
    c = md()

    lines = [
        '# M11-P 2.6.1 still R2Y direct API identity scan', '',
        f'- canonical SHA-256: `{digest}`',
        f'- relocation delta: `0x{DELTA:08X}`',
        f'- per-function scan window: `0x{SCAN:X}` bytes', '',
    ]
    found = 0
    for target in TARGETS:
        refs = refs_for_target(c, data, target)
        lines += [f'## `0x{target:08X}`', '']
        if not refs:
            lines += ['- no Leica R2Y/API assertion string reconstructed in bounded prologue scan', '']
            continue
        # Deduplicate repeated construction of the same string.
        seen = set()
        for lo_at, hi_at, runtime, static, text in refs:
            key = (runtime, text)
            if key in seen:
                continue
            seen.add(key); found += 1
            lines.append(f'- code `0x{lo_at:08X}`/`0x{hi_at:08X}` -> runtime `0x{runtime:08X}` -> file `0x{static:08X}`')
            lines.append(f'  - `{text}`')
        lines.append('')

    lines += [
        '## Interpretation', '',
        f'- reconstructed assertion/API strings: `{found}`',
        '- A direct function name is accepted only when its own bounded code reconstructs the matching Leica assertion string.',
        '- Absence of a name is not treated as absence of the stage; it only means this string-based identity probe did not close that target.',
        '- RENDER1H remains frozen; this is an API identity/provenance probe.', ''
    ]
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text('\n'.join(lines) + '\n')
    print(a.output)


if __name__ == '__main__':
    main()
