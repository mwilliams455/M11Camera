#!/usr/bin/env python3
"""Read-only MCC continuation: ordinal-table exclusion and entry-boundary audit.

Raw word/branch matches are candidates, not CFG-proven code references. This
probe deliberately includes addresses immediately BEFORE the previously pinned
writer: matching assertion strings proves API identity but not entry alignment.
No renderer, calibration, photographic controls or firmware bytes are changed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED = '28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
DELTA = 0x3FAA87D0
MCC = 0x01B2D324
RETURN = 0x01B60320
LEAD = 0x0322DB4C
STRIDE = 0xBC
CONTROLS = (0x01B2397C, 0x01B1B9C8, 0x01B1CDA4, 0x01B209D4,
            0x01B20BAC, 0x01B21798, 0x01B24DEC, 0x01B253C0,
            0x01B25E0C, 0x01B258A8, 0x01B21E6C, 0x01B1EA1C)


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def arm_branch(off: int, word: int):
    # ARM B/BL, not unconditional-space BLX-immediate (Thumb destination).
    if word >> 28 == 15 or word & 0x0E000000 != 0x0A000000:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    target = (off + 8 + 4 * imm) & 0xFFFFFFFF
    return {'at': off, 'word': word, 'target': target,
            'kind': 'BL' if word & 0x01000000 else 'B', 'condition': word >> 28}


def ordinal_chain(data: bytes):
    if u32(data, LEAD) != 0x78C:
        raise ValueError('canonical size-word anchor mismatch')
    lo = hi = LEAD
    while lo >= STRIDE and u32(data, lo - STRIDE) + 1 == u32(data, lo):
        lo -= STRIDE
    while hi + STRIDE + 4 <= len(data) and u32(data, hi + STRIDE) == u32(data, hi) + 1:
        hi += STRIDE
    return {'start': lo, 'end': hi, 'first_id': u32(data, lo),
            'last_id': u32(data, hi), 'stride': STRIDE,
            'count': (hi - lo) // STRIDE + 1,
            'lead': LEAD, 'lead_value': u32(data, LEAD)}


def run(data: bytes):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError(f'noncanonical firmware: {digest}')
    chain = ordinal_chain(data)
    if chain['count'] < 43:
        raise ValueError('ordinal exclusion must reproduce at least the 43-record artifact witness')
    near, external, pointers = [], [], []
    positive = {f'{t:08X}': [] for t in CONTROLS}
    for n, (word,) in enumerate(struct.iter_unpack('<I', data[:len(data) & ~3])):
        off = n * 4
        branch = arm_branch(off, word)
        if branch:
            dest = branch['target']
            if MCC - 0x400 <= dest < MCC + 0x100:
                near.append(branch)
            if MCC - 0x400 <= dest <= RETURN and not MCC - 0x400 <= off <= RETURN:
                external.append(branch)
            if dest in CONTROLS:
                positive[f'{dest:08X}'].append(branch)
        for domain, base in (('static', 0), ('runtime_delta_hypothesis', DELTA)):
            target = (word - base) & 0xFFFFFFFF
            if MCC - 0x400 <= target < MCC + 0x100:
                pointers.append({'at': off, 'word': word, 'target': target, 'domain': domain})
    return {'sha256': digest, 'ordinal_chain': chain,
            'near_entry_branch_candidates': near,
            'external_body_branch_candidates': external,
            'near_entry_pointer_candidates': pointers,
            'known_direct_target_controls': positive}


def disasm(data: bytes, start: int, stop: int):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    cs.skipdata = True
    return [f'{i.address:08X}: {i.bytes.hex():8s}  {i.mnemonic:9s} {i.op_str}'
            for i in cs.disasm(data[start:stop], start)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output-dir', required=True, type=Path)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    result = run(data)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / 'entryaudit1a.json').write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# M11 MCC ENTRYAUDIT1A', '', f"Canonical SHA-256: `{result['sha256']}`", '',
             '## 0x78C lead: fixed-stride ordinal chain', '',
             '```json', json.dumps(result['ordinal_chain'], indent=2), '```', '',
             'The 0x78C word is in an ordinal field, not evidence of a CtrlMultiAxis size.',
             'The exact subsystem owning this record table is not established here.', '']
    for name in ('near_entry_branch_candidates', 'external_body_branch_candidates',
                 'near_entry_pointer_candidates'):
        rows = result[name]
        lines += [f'## {name}: {len(rows)}', '', '```text']
        for r in rows[:300]:
            lines.append(' '.join(f'{k}=0x{v:08X}' if isinstance(v, int) else f'{k}={v}' for k, v in r.items()))
        lines += ['```', '']
    lines += ['## Known direct-target positive controls', '']
    for target, rows in result['known_direct_target_controls'].items():
        lines.append(f'- 0x{target}: {len(rows)} raw branch candidates; ' + ', '.join(f"0x{r['at']:08X}" for r in rows[:20]))
    for start, stop, label in ((MCC - 0x300, MCC + 0x200, 'Writer entry neighborhood'),
                              (RETURN - 0x80, RETURN + 0x180, 'Writer return neighborhood')):
        lines += ['', f'## {label}', '', '```text'] + disasm(data, start, stop) + ['```']
    origins = sorted({r['at'] for r in result['near_entry_branch_candidates']
                      if not MCC - 0x400 <= r['at'] <= RETURN})
    for origin in origins[:40]:
        lines += ['', f'## External candidate call context 0x{origin:08X}', '', '```text']
        lines += disasm(data, max(0, origin - 0x80), min(len(data), origin + 0x40)) + ['```']
    lines += ['', '## Evidence gate', '',
              '- Branch and pointer matches are candidates until code boundary / CFG / argument dataflow validates them.',
              '- The asserted API identity is retained; the exact entry boundary is independently audited.',
              '- No MCC coefficients or active still invocation are inferred merely from a raw branch match.',
              '- DIRECTK1A, identity CC0, frozen RENDER1H, Cat25 inactive and Cat42 policy remain unchanged.', '']
    text = '\n'.join(lines)
    (out / 'entryaudit1a.md').write_text(text)
    print(text)


if __name__ == '__main__':
    main()
