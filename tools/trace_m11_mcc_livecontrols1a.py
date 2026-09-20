#!/usr/bin/env python3
"""Read-only follow-on: driver availability is not proof of still-path use.

Collect exact MCC-related strings, their adjacent A32 MOVW/MOVT references,
nearby prologue candidates, direct call candidates, and bounded still-control
and common-control disassembly. No default MCC coefficients are synthesized.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
import re
import struct
from pathlib import Path
from trace_m11_mcc_entryaudit1a import EXPECTED, DELTA, MCC, arm_branch, disasm, u32

CODE_LO = 0x01600000
CODE_HI = 0x01C90000


def halfword_imm(word):
    return ((word >> 4) & 0xF000) | (word & 0xFFF)


def cstring(data, off):
    if not 0 <= off < len(data):
        return None
    end = data.find(b'\0', off, min(len(data), off + 240))
    if end < off + 5:
        return None
    raw = data[off:end]
    return raw.decode('ascii') if all(32 <= v < 127 or v == 9 for v in raw) else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError('noncanonical firmware: ' + digest)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    strings = []
    for m in re.finditer(rb'[\x20-\x7e]{6,240}\x00', data):
        text = m.group()[:-1].decode('ascii')
        if re.search(r'multi[_ -]?axis|mccsl|mccen|mccmd|r2y.*mcc|mcc.*r2y', text, re.I):
            strings.append({'at': m.start(), 'text': text})
    prologues = []
    for at in range(CODE_LO, CODE_HI - 4, 4):
        # Known GCC frame-pointer ABI: push {...,fp,lr} / add fp,sp,#N.
        w, nxt = u32(data, at), u32(data, at + 4)
        if w & 0xFFFF4800 == 0xE92D4800 and nxt & 0xFFFFF000 == 0xE28DB000:
            prologues.append(at)
    references, api_refs = [], []
    for at in range(CODE_LO, CODE_HI - 4, 4):
        w, t = u32(data, at), u32(data, at + 4)
        if w & 0x0FF00000 != 0x03000000 or t & 0x0FF00000 != 0x03400000:
            continue
        if (w >> 12) & 15 != (t >> 12) & 15 or w >> 28 != t >> 28:
            continue
        runtime = halfword_imm(w) | (halfword_imm(t) << 16)
        static = (runtime - DELTA) & 0xFFFFFFFF
        text = cstring(data, static)
        if not text or not ('R2Y' in text or re.search(r'multi[_ -]?axis|mccsl', text, re.I)):
            continue
        k = bisect.bisect_right(prologues, at) - 1
        entry = prologues[k] if k >= 0 and at - prologues[k] <= 0x400 else None
        row = {'at': at, 'runtime': runtime, 'static': static,
               'text': text, 'nearby_prologue_candidate': entry}
        api_refs.append(row)
        if re.search(r'multi[_ -]?axis|mccsl|mccen|mccmd|r2y.*mcc|mcc.*r2y', text, re.I):
            references.append(row)
    targets = {MCC} | {r['nearby_prologue_candidate'] for r in references
                     if r['nearby_prologue_candidate'] is not None}
    calls = []
    for at in range(CODE_LO, CODE_HI, 4):
        branch = arm_branch(at, u32(data, at))
        if branch and branch['target'] in targets:
            calls.append(branch)
    result = {'sha256': digest, 'candidate_code_bounds': [CODE_LO, CODE_HI],
              'strings': strings, 'mcc_string_references': references,
              'all_r2y_api_string_references': api_refs,
              'mcc_related_prologue_candidates': sorted(targets),
              'mcc_related_direct_branch_candidates': calls}
    (out / 'livecontrols1a.json').write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# M11 MCC LIVECONTROLS1A', '', f'Canonical SHA-256: `{digest}`', '',
             '## Matching firmware strings', '']
    for r in strings:
        lines.append(f"- 0x{r['at']:08X}: {r['text']}")
    lines += ['', '## MCC-related code references', '']
    for r in references:
        entry = r['nearby_prologue_candidate']
        lines.append(f"- 0x{r['at']:08X} -> file 0x{r['static']:08X}: {r['text']}; prologue candidate=" + (f'0x{entry:08X}' if entry is not None else 'none'))
    lines += ['', '## MCC-related direct branch candidates', '', '```json', json.dumps(calls, indent=2), '```', '',
              '## R2Y assertion/API identities near prologue candidates', '']
    seen = set()
    for r in api_refs:
        entry = r['nearby_prologue_candidate']
        key = (entry, r['text'])
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- ref=0x{r['at']:08X}; entry=" + (f'0x{entry:08X}' if entry is not None else 'none') + ': ' + r['text'])
    lines += ['', '## Gate', '',
              'Prologue candidates and raw branch candidates require instruction/argument validation.',
              'MCCSL is a placement selector, not sufficient evidence of live MCC coefficient programming.',
              'Keep all photographic renderer behavior frozen.', '']
    (out / 'livecontrols1a.md').write_text('\n'.join(lines))
    windows = [(0x0172B000, 0x01732000, 'still_iq_wrappers'),
               (0x01B23800, 0x01B24DEC, 'r2y_common_ctrl'),
               (0x01B1B9C8, 0x01B1CDA4, 'r2y_init_ctrl')]
    for start, stop, name in windows:
        (out / (name + '.asm')).write_text('\n'.join(disasm(data, start, stop)) + '\n')
    for entry in sorted(targets):
        (out / f'api_{entry:08X}.asm').write_text('\n'.join(disasm(data, entry, entry + 0x300)) + '\n')
    for r in calls:
        at = r['at']
        (out / f'caller_{at:08X}.asm').write_text('\n'.join(disasm(data, at - 0x100, at + 0x100)) + '\n')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
