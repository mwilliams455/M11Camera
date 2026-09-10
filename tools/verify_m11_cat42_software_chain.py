#!/usr/bin/env python3
"""Fail-closed regression proof for the M11-P Category-42 software chain.

This verifies primary-firmware facts that are now closed:
  * the CSP request selects category 42;
  * Cat42 descriptors are ISO-range + saturation-state records, each 44 bytes;
  * the resolver call returns the selected serialized record pointer;
  * the wrapper consumes every serialized halfword at offsets 0x00..0x2a in order;
  * only representation-width normalization (UXTH and, for native byte fields,
    UXTB) occurs before the local CSP control structure is passed to the proven
    Milbeaut register programmer at 0x01b68b80.

It intentionally does NOT claim the internal Milbeaut CSYKY reference equation,
endpoint direction, border comparator, or multiply rounding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

WRAPPER = 0x01731970
LOOKUP_CALL = 0x01731B34
LOOKUP = 0x0178D0A8
COPY_START = 0x01731C24
CSP_CALL = 0x01731DB0
CSP_SETTER = 0x01B68B80

EXPECTED_STATES = [-3, -2, -1, 0, 1, 2, 3, 10]
EXPECTED_FLAGS = 0x206
EXPECTED_DEPS = {s: [0, 200000, s] for s in EXPECTED_STATES}
EXPECTED_MAP_SIZE = 44
EXPECTED_SERIAL_OFFSETS = list(range(0, 44, 2))
BYTE_FIELDS = {0x00, 0x02, 0x04, 0x1C, 0x1E, 0x20}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def bl_target(addr: int, word: int) -> int | None:
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (addr + 8 + (imm << 2)) & 0xFFFFFFFF


def disasm(data: bytes, start: int, end: int):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    return list(md.disasm(data[start:end], start))


def parse_source_load(ins) -> int | None:
    # Canonical source access is: ldr r3,[fp,#-8] ; ldrh/ldrsh r3,[r3,#imm]
    if ins.mnemonic not in ('ldrh', 'ldrsh'):
        return None
    m = re.fullmatch(r'r3, \[r3(?:, #(0x[0-9a-f]+|\d+))?\]', ins.op_str.lower())
    if not m:
        return None
    return int(m.group(1), 0) if m.group(1) else 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--json', type=Path, required=True)
    ap.add_argument('--markdown', type=Path, required=True)
    a = ap.parse_args()

    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f'unexpected SHA {digest}')

    # Pin control-flow endpoints.
    if bl_target(LOOKUP_CALL, u32(data, LOOKUP_CALL)) != LOOKUP:
        raise AssertionError('Cat42 lookup call target changed')
    if bl_target(CSP_CALL, u32(data, CSP_CALL)) != CSP_SETTER:
        raise AssertionError('CSP setter call target changed')

    # Pin request construction immediately before lookup.
    req = disasm(data, 0x01731B0C, LOOKUP_CALL + 4)
    req_text = [f'{x.mnemonic} {x.op_str}'.lower() for x in req]
    for needed in ('mov r3, #8', 'mov r3, #0x2a'):
        if needed not in req_text:
            raise AssertionError(f'missing request constant: {needed}')

    # Pin Category-42 descriptors and dependency shape.
    _, _, _, descs = parse_r2y(data)
    rows = []
    for d in descs:
        if d.get('category') != 42:
            continue
        deps = d.get('dependencies_s32', [])
        state = deps[2] if len(deps) >= 3 else None
        rows.append({
            'state': state,
            'flags': d.get('flags'),
            'deps': deps,
            'map_size': d.get('map_size'),
            'map_offset_abs': d.get('map_offset_abs'),
        })
    rows.sort(key=lambda x: 999 if x['state'] is None else x['state'])
    states = [x['state'] for x in rows]
    if states != EXPECTED_STATES:
        raise AssertionError(f'Cat42 state set changed: {states}')
    for row in rows:
        s = row['state']
        if row['flags'] != EXPECTED_FLAGS:
            raise AssertionError(f'Cat42 flags changed for {s}: {row["flags"]:#x}')
        if row['deps'] != EXPECTED_DEPS[s]:
            raise AssertionError(f'Cat42 dependencies changed for {s}: {row["deps"]}')
        if row['map_size'] != EXPECTED_MAP_SIZE:
            raise AssertionError(f'Cat42 map size changed for {s}: {row["map_size"]}')

    # Recover the 22 serialized source-field reads. Each field access is preceded
    # by loading the selected record pointer from [fp,#-8]. Between source load
    # and destination store only representation normalization is allowed.
    ins = disasm(data, COPY_START, CSP_CALL)
    source_rows = []
    for idx, cur in enumerate(ins):
        off = parse_source_load(cur)
        if off is None:
            continue
        if idx == 0 or not (ins[idx-1].mnemonic == 'ldr' and ins[idx-1].op_str.lower() == 'r3, [fp, #-8]'):
            raise AssertionError(f'source field load at {cur.address:#x} lost canonical pointer reload')
        j = idx + 1
        transforms = []
        store = None
        while j < len(ins) and j <= idx + 4:
            x = ins[j]
            if x.mnemonic in ('uxth', 'uxtb'):
                transforms.append(x.mnemonic)
            elif x.mnemonic in ('strh', 'strb'):
                store = x
                break
            else:
                raise AssertionError(f'unexpected arithmetic between source and local CSP field at {cur.address:#x}: {x.mnemonic} {x.op_str}')
            j += 1
        if store is None:
            raise AssertionError(f'no local store after source field {off:#x}')
        expected_store = 'strb' if off in BYTE_FIELDS else 'strh'
        if store.mnemonic != expected_store:
            raise AssertionError(f'field {off:#x} expected {expected_store}, got {store.mnemonic}')
        if 'uxth' not in transforms:
            raise AssertionError(f'field {off:#x} missing 16-bit normalization')
        if off in BYTE_FIELDS and 'uxtb' not in transforms:
            raise AssertionError(f'byte field {off:#x} missing 8-bit normalization')
        if off not in BYTE_FIELDS and 'uxtb' in transforms:
            raise AssertionError(f'16-bit field {off:#x} unexpectedly narrowed to byte')
        source_rows.append({
            'source_offset': off,
            'load_address': cur.address,
            'load': cur.mnemonic,
            'normalization': transforms,
            'store': store.mnemonic,
            'store_address': store.address,
            'store_operand': store.op_str,
        })

    actual_offsets = [x['source_offset'] for x in source_rows]
    if actual_offsets != EXPECTED_SERIAL_OFFSETS:
        raise AssertionError(f'serialized field sequence changed: {actual_offsets}')

    # Pin final ABI setup: native pipe/channel in r0, local CSP struct in r1.
    tail = disasm(data, 0x01731D9C, CSP_CALL + 4)
    tail_text = [f'{x.mnemonic} {x.op_str}'.lower() for x in tail]
    for needed in ('sub r3, fp, #0x34', 'mov r0, r2', 'mov r1, r3'):
        if needed not in tail_text:
            raise AssertionError(f'missing final CSP ABI setup: {needed}')

    report = {
        'schema': 'm11camera.research.cat42_software_chain.v1',
        'sha256': digest,
        'wrapper': hex(WRAPPER),
        'lookup': {'callsite': hex(LOOKUP_CALL), 'target': hex(LOOKUP)},
        'csp_setter': {'callsite': hex(CSP_CALL), 'target': hex(CSP_SETTER)},
        'descriptor_flags': hex(EXPECTED_FLAGS),
        'states': rows,
        'serialized_source_fields': source_rows,
        'closed': {
            'category_request_42': True,
            'iso_saturation_dependency_records': True,
            'all_22_serialized_fields_consumed_in_order': True,
            'no_photographic_arithmetic_during_transfer': True,
            'native_width_normalization_only': True,
        },
        'still_open': [
            'CSYKY endpoint direction / Y-C mixing equation',
            'internal CSP reference/chroma magnitude construction',
            'exact border comparator and fixed-point multiply rounding',
        ],
    }

    lines = [
        '# M11-P Category-42 software-chain regression proof', '',
        f'- SHA-256: `{digest}`',
        '- result: **PASS**',
        f'- Category-42 descriptors: `{len(rows)}`',
        f'- descriptor flags: `0x{EXPECTED_FLAGS:x}` = category + ISO range + saturation-state selectors',
        f'- serialized CSP fields consumed: `{len(source_rows)}/22` in exact offsets `0x00..0x2a`',
        '- transfer arithmetic: **none**; only UXTH plus UXTB on native byte/control fields',
        f'- final CSP programmer: `0x{CSP_SETTER:08x}`', '',
        '## Closed software semantics', '',
        'The R2YS resolver selects one 44-byte Category-42 record by category 42, ISO range 0..200000, and exact saturation state (-3..+3 or +10). The wrapper reads every serialized 16-bit field in order and reconstructs the native CSP control structure without changing numeric parameter values; byte/control fields are narrowed to their native width. The resulting structure is passed directly to the proven Milbeaut CSP register programmer.', '',
        '## Still hardware-internal', '',
        '- CSYKY=8 endpoint direction and exact Y/C mix equation',
        '- exact chroma-reference magnitude construction',
        '- exact border ownership and signed multiply/rounding', '',
        'These remaining items are not inferred by this verifier.', '',
    ]

    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.markdown.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(report, indent=2) + '\n')
    a.markdown.write_text('\n'.join(lines) + '\n')
    print(a.markdown)


if __name__ == '__main__':
    main()
