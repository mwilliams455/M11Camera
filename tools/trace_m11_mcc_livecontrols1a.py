#!/usr/bin/env python3
"""Read-only MCC live-control census with mandatory known-API positive controls.

Driver availability is not proof of still-path use. Prologue and branch hits
remain candidates until their instruction and argument dataflow is validated.
Accept CR/LF/TAB in firmware C strings: SDK assertions contain trailing newlines.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
import re
from pathlib import Path
from trace_m11_mcc_entryaudit1a import EXPECTED, DELTA, MCC, arm_branch, disasm, u32

CODE_LO = 0x01600000
CODE_HI = 0x01C90000
MCC_NAME = 'Im_R2Y_Ctrl_Multi_Axis'
PATTERN = re.compile(r'multi[_ -]?axis|mccsl|mccen|mccmd|r2y.*mcc|mcc.*r2y', re.I)


def halfword_imm(word):
    return ((word >> 4) & 0xF000) | (word & 0xFFF)


def cstring(data, off):
    if not 0 <= off < len(data):
        return None
    end = data.find(b'\0', off, min(len(data), off + 512))
    if end < off + 5:
        return None
    raw = data[off:end]
    return raw.decode('ascii') if all(32 <= v < 127 or v in (9, 10, 13) for v in raw) else None


def display(text):
    return text.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    assert cstring(b'assertion error\n\0', 0) == 'assertion error\n'
    assert cstring(b'assertion error\r\n\0', 0) == 'assertion error\r\n'
    assert cstring(b'assertion\tcontrol\0', 0) == 'assertion\tcontrol'
    assert cstring(b'assertion\x01error\0', 0) is None
    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError('noncanonical firmware: ' + digest)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    strings = []
    for m in re.finditer(rb'[\x09\x0a\x0d\x20-\x7e]{6,512}\x00', data):
        text = m.group()[:-1].decode('ascii')
        if PATTERN.search(text):
            strings.append({'at': m.start(), 'text': text})
    prologues = []
    for at in range(CODE_LO, CODE_HI - 4, 4):
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
        if not text or not ('R2Y' in text or PATTERN.search(text)):
            continue
        k = bisect.bisect_right(prologues, at) - 1
        entry = prologues[k] if k >= 0 and at - prologues[k] <= 0x400 else None
        row = {'at': at, 'runtime': runtime, 'static': static,
               'text': text, 'nearby_prologue_candidate': entry}
        api_refs.append(row)
        if PATTERN.search(text):
            references.append(row)
    gates = {
        'cstring_four_unit_tests': True,
        'known_mcc_assertion_found': any(MCC_NAME in r['text'] for r in strings),
        'known_mcc_entry_reference_found': any(MCC_NAME in r['text'] and r['nearby_prologue_candidate'] == MCC for r in references),
    }
    (out / 'positive_controls.json').write_text(json.dumps(gates, indent=2) + '\n')
    if not all(gates.values()):
        raise RuntimeError('MCC positive-control failure; negative results invalid: ' + repr(gates))
    targets = {MCC} | {r['nearby_prologue_candidate'] for r in references
                     if r['nearby_prologue_candidate'] is not None}
    calls = []
    for at in range(CODE_LO, CODE_HI, 4):
        branch = arm_branch(at, u32(data, at))
        if branch and branch['target'] in targets:
            calls.append(branch)
    result = {'sha256': digest, 'positive_controls': gates,
              'candidate_code_bounds': [CODE_LO, CODE_HI],
              'strings': strings, 'mcc_string_references': references,
              'all_r2y_api_string_references': api_refs,
              'mcc_related_prologue_candidates': sorted(targets),
              'mcc_related_direct_branch_candidates': calls}
    (out / 'livecontrols1a.json').write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# M11 MCC LIVECONTROLS1A — assertion parser corrected', '',
             f'Canonical SHA-256: `{digest}`', '',
             '## Mandatory positive controls', '', '```json', json.dumps(gates, indent=2), '```', '',
             '## Matching firmware strings', '']
    for r in strings:
        lines.append(f"- 0x{r['at']:08X}: {display(r['text'])}")
    lines += ['', '## MCC-related code references', '']
    for r in references:
        entry = r['nearby_prologue_candidate']
        lines.append(f"- 0x{r['at']:08X} -> file 0x{r['static']:08X}: {display(r['text'])}; prologue candidate=" + (f'0x{entry:08X}' if entry is not None else 'none'))
    lines += ['', '## MCC-related direct branch candidates', '', '```json', json.dumps(calls, indent=2), '```', '',
              '## R2Y assertion/API identities near prologue candidates', '']
    seen = set()
    for r in api_refs:
        entry = r['nearby_prologue_candidate']
        key = (entry, r['text'])
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- ref=0x{r['at']:08X}; entry=" + (f'0x{entry:08X}' if entry is not None else 'none') + ': ' + display(r['text']))
    lines += ['', '## Gate', '',
              'Prologue candidates and raw branch candidates require instruction/argument validation.',
              'MCCSL is a placement selector, not sufficient evidence of live MCC coefficient programming.',
              'The pre-fix empty-string result is invalidated by its failed known-API positive control.',
              'Keep all photographic renderer behavior frozen.', '']
    (out / 'livecontrols1a.md').write_text('\n'.join(lines))
    windows = [(0x0172B000, 0x01734000, 'still_iq_wrappers'),
               (0x01B23800, 0x01B24DEC, 'r2y_common_ctrl'),
               (0x01B1B9C8, 0x01B1CDA4, 'r2y_init_ctrl'),
               (0x01B1CDA4, 0x01B209D4, 'r2y_control_body'),
               (0x0176FC00, 0x01770080, 'still_dispatch_control_calls')]
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
