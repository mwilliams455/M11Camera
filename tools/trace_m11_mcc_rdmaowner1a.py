#!/usr/bin/env python3
"""Read-only extraction of the object returned by the proven MCC RDMA helper.

The helper returns an address-control object, NOT necessarily coefficients.
Do not equate this 0x7F4 stride with the 0x78C CtrlMultiAxis coefficient layout.
References remain candidates until code/dataflow and live invocation are proven.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from trace_m11_mcc_entryaudit1a import EXPECTED, DELTA, disasm, u32
from trace_m11_mcc_livecontrols1a import halfword_imm

RUNTIME = 0x42B66EB8
STATIC = RUNTIME - DELTA
STRIDE = 0x7F4
PIPES = 3
HELPER = 0x01B6B388


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError('noncanonical firmware: ' + digest)
    # Instruction-backed provenance, independent of a size/pointer coincidence.
    expected = bytes.fromhex('05305be5 f42700e3 920302e0 b83e06e3 b63244e3 032082e0 0c301be5 002083e5 0030a0e3')
    if data[0x01B6B3D8:0x01B6B3FC] != expected:
        raise ValueError('RDMA helper return-expression instruction gate failed')
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    blocks = []
    for pipe in range(PIPES):
        start = STATIC + STRIDE * pipe
        raw = data[start:start + STRIDE]
        words = list(struct.unpack('<' + 'I' * (STRIDE // 4), raw))
        blocks.append({'pipe': pipe, 'static': start, 'runtime': RUNTIME + STRIDE * pipe,
                       'length': STRIDE, 'sha256': hashlib.sha256(raw).hexdigest(),
                       'words': words})
        (out / f'mcc_rdma_address_object_pipe{pipe}.bin').write_bytes(raw)
    refs, pointers = [], []
    for at in range(0x01600000, 0x01C90000 - 4, 4):
        w, t = u32(data, at), u32(data, at + 4)
        if w & 0x0FF00000 != 0x03000000 or t & 0x0FF00000 != 0x03400000:
            continue
        if (w >> 12) & 15 != (t >> 12) & 15 or w >> 28 != t >> 28:
            continue
        value = halfword_imm(w) | (halfword_imm(t) << 16)
        for domain, base in (('runtime', RUNTIME), ('static', STATIC)):
            if base <= value < base + PIPES * STRIDE:
                refs.append({'at': at, 'value': value, 'offset': value - base, 'domain': domain})
    for n, (value,) in enumerate(struct.iter_unpack('<I', data[:len(data) & ~3])):
        for domain, base in (('runtime', RUNTIME), ('static', STATIC)):
            if base <= value < base + PIPES * STRIDE:
                pointers.append({'at': n * 4, 'value': value, 'offset': value - base, 'domain': domain})
    comparisons = []
    for pipe in (1, 2):
        deltas = {}
        for a, b in zip(blocks[0]['words'], blocks[pipe]['words']):
            d = (b - a) & 0xFFFFFFFF
            deltas[f'0x{d:08X}'] = deltas.get(f'0x{d:08X}', 0) + 1
        comparisons.append({'pipe': pipe, 'delta_histogram_vs_pipe0': deltas})
    result = {'canonical_sha256': digest, 'helper': HELPER,
              'helper_return_instruction_gate': True,
              'runtime_base': RUNTIME, 'relocation_delta': DELTA, 'static_base': STATIC,
              'stride': STRIDE, 'blocks': blocks, 'pipe_comparisons': comparisons,
              'adjacent_movw_movt_candidates': refs, 'raw_aligned_pointer_candidates': pointers}
    (out / 'rdmaowner1a.json').write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# M11 MCC RDMAOWNER1A', '', f'Canonical SHA-256: `{digest}`', '',
             '## Proven helper return expression', '',
             '`Im_R2Y_Get_RdmaAddr_Multi_Axis_Cntl` at `0x01B6B388` returns',
             '`0x42B66EB8 + pipe * 0x7F4` through its output pointer.',
             'Runtime base minus the independently recovered relocation delta is file `0x030BE6E8`.',
             'This is an address-control object, not a recovered Leica colour-coefficient object.', '',
             '```text'] + disasm(data, HELPER, 0x01B6B408) + ['```', '', '## Cross-pipe comparison', '',
             '```json', json.dumps(comparisons, indent=2), '```']
    for title, rows in (('Adjacent MOVW/MOVT candidates', refs), ('Raw aligned pointer candidates', pointers)):
        lines += ['', f'## {title}: {len(rows)}', '', '```text']
        for r in rows[:250]:
            lines.append(f"0x{r['at']:08X}: 0x{r['value']:08X} domain={r['domain']} offset=0x{r['offset']:X}")
        lines += ['```']
    lines += ['', '## Lossless word layout (three pipe objects)', '', '| Offset | Pipe 0 | Pipe 1 | Pipe 2 |', '| --- | --- | --- | --- |']
    for i in range(STRIDE // 4):
        lines.append(f'| 0x{i*4:03X} | ' + ' | '.join(f"0x{b['words'][i]:08X}" for b in blocks) + ' |')
    lines += ['', '## Evidence boundary', '',
              'The helper establishes ownership/type family and exact address/stride. The returned data must still be classified from its contents.',
              'No still-path consumer or non-identity MCC coefficient program is inferred from helper availability.',
              'A raw pointer candidate in compressed/data regions is not a code reference.',
              'All rendering behavior remains frozen.', '']
    (out / 'rdmaowner1a.md').write_text('\n'.join(lines))
    for r in refs:
        at = r['at']
        (out / f'movref_{at:08X}.asm').write_text('\n'.join(disasm(data, at - 0x80, at + 0x80)) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'blocks'}, indent=2))


if __name__ == '__main__':
    main()
