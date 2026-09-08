#!/usr/bin/env python3
"""Probe extracted M11-P image-pipeline assets for recorded tone/gamma structures.

This is deliberately evidence-driven.  It does not assume a descriptor database
layout and it does not fabricate missing samples.

Tone evidence recovered in the original investigation:
- seven contrast states (-3..+3)
- 1024 uint16 gain samples per state
- Q12 unity = 4096
- contrast -3 is exactly constant 4096
- recorded min/max ranges for the other six states

Gamma evidence recovered in the original investigation:
- a 256 x uint16 coarse table in the 10-bit 0..1023 output domain
- a 2048-byte companion payload, interpreted as 256 groups x 16 nibbles
- 12-bit input -> roughly 4096 output positions

The script locates structures matching those constraints and emits hashes,
offsets, statistics and (for an exact tone-family match) the derived samples.
It never copies arbitrary firmware bytes into the result.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import struct
from pathlib import Path
from typing import Iterable

TONE_STATES = [-3, -2, -1, 0, 1, 2, 3]
TONE_EXPECTED_RANGES = {
    -3: (4096, 4096),
    -2: (3004, 4348),
    -1: (2185, 4602),
     0: (1911, 4867),
     1: (1365, 5290),
     2: (1057, 5742),
     3: (793, 6225),
}
TONE_SAMPLES = 1024
TONE_BYTES = TONE_SAMPLES * 2
TONE_FAMILY_BYTES = len(TONE_STATES) * TONE_BYTES


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unpack_u16(data: bytes, offset: int, count: int, endian: str) -> list[int]:
    fmt = ('<' if endian == 'le' else '>') + f'{count}H'
    return list(struct.unpack_from(fmt, data, offset))


def tone_block_stats(values: list[int]) -> dict:
    diffs = [b - a for a, b in zip(values, values[1:])]
    second = [b - a for a, b in zip(diffs, diffs[1:])]
    return {
        'min': min(values),
        'max': max(values),
        'first': values[0],
        'last': values[-1],
        'mean': sum(values) / len(values),
        'unique': len(set(values)),
        'monotonic_increases': sum(d > 0 for d in diffs),
        'monotonic_decreases': sum(d < 0 for d in diffs),
        'max_abs_first_difference': max((abs(x) for x in diffs), default=0),
        'second_difference_l1': sum(abs(x) for x in second),
    }


def range_error(block_ranges: list[tuple[int, int]], order: list[int]) -> int:
    err = 0
    for got, state in zip(block_ranges, order):
        exp = TONE_EXPECTED_RANGES[state]
        err += abs(got[0] - exp[0]) + abs(got[1] - exp[1])
    return err


def find_unity_runs(data: bytes, endian: str) -> list[int]:
    word = struct.pack('<H' if endian == 'le' else '>H', 4096)
    run = word * TONE_SAMPLES
    out = []
    start = 0
    while True:
        p = data.find(run, start)
        if p < 0:
            return out
        out.append(p)
        start = p + 2


def analyze_tone_family_at(data: bytes, start: int, endian: str, order: list[int]) -> dict | None:
    if start < 0 or start + TONE_FAMILY_BYTES > len(data):
        return None
    blocks = []
    ranges = []
    for i, state in enumerate(order):
        vals = unpack_u16(data, start + i*TONE_BYTES, TONE_SAMPLES, endian)
        stats = tone_block_stats(vals)
        blocks.append({'state': state, 'stats': stats})
        ranges.append((stats['min'], stats['max']))
    error = range_error(ranges, order)
    exact = error == 0
    return {
        'start': start,
        'start_hex': hex(start),
        'end': start + TONE_FAMILY_BYTES,
        'endian': endian,
        'state_order': order,
        'range_error_l1': error,
        'exact_recorded_range_match': exact,
        'family_sha256': sha256(data[start:start+TONE_FAMILY_BYTES]),
        'blocks': blocks,
    }


def find_tone_candidates(data: bytes) -> list[dict]:
    candidates = []
    orders = [TONE_STATES, list(reversed(TONE_STATES))]
    for endian in ('le', 'be'):
        for unity_start in find_unity_runs(data, endian):
            # The constant -3 block can sit anywhere in a hypothetical seven-block
            # window while we are still uncertain about storage order.  Evaluate
            # every possible block position and both state directions.
            for block_index in range(7):
                start = unity_start - block_index*TONE_BYTES
                for order in orders:
                    item = analyze_tone_family_at(data, start, endian, order)
                    if item is not None:
                        item['unity_run_start'] = unity_start
                        item['unity_run_start_hex'] = hex(unity_start)
                        item['unity_block_index'] = block_index
                        candidates.append(item)
    candidates.sort(key=lambda x: (x['range_error_l1'], x['start'], x['endian']))
    # Deduplicate identical windows/order/endian.
    unique = []
    seen = set()
    for c in candidates:
        key = (c['start'], c['endian'], tuple(c['state_order']))
        if key not in seen:
            seen.add(key); unique.append(c)
    return unique


def write_tone_csv(path: Path, data: bytes, candidate: dict) -> None:
    start = candidate['start']; endian = candidate['endian']; order = candidate['state_order']
    values = {
        state: unpack_u16(data, start+i*TONE_BYTES, TONE_SAMPLES, endian)
        for i, state in enumerate(order)
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        fields = ['index', 'input_norm'] + [f'gain_q12_{state:+d}' for state in TONE_STATES]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for i in range(TONE_SAMPLES):
            row = {'index': i, 'input_norm': i/(TONE_SAMPLES-1)}
            for state in TONE_STATES:
                row[f'gain_q12_{state:+d}'] = values[state][i]
            w.writerow(row)


def gamma_coarse_stats(values: list[int]) -> dict:
    d1 = [b-a for a,b in zip(values, values[1:])]
    d2 = [b-a for a,b in zip(d1, d1[1:])]
    return {
        'first': values[0], 'last': values[-1],
        'min': min(values), 'max': max(values),
        'unique': len(set(values)),
        'nondecreasing': all(d >= 0 for d in d1),
        'strict_increase_count': sum(d > 0 for d in d1),
        'zero_step_count': sum(d == 0 for d in d1),
        'first_difference_min': min(d1) if d1 else 0,
        'first_difference_max': max(d1) if d1 else 0,
        'second_difference_l1': sum(abs(x) for x in d2),
    }


def gamma_score(stats: dict) -> float:
    # Lower is better. Strongly prefer the recorded 10-bit output domain and a
    # monotonic curve spanning nearly the full 0..1023 range.
    if not stats['nondecreasing']:
        return 1e9
    if stats['min'] < 0 or stats['max'] > 1023:
        return 1e9
    score = 0.0
    score += abs(stats['first'] - 0) * 5
    score += abs(stats['last'] - 1023) * 5
    score += max(0, 128 - stats['unique']) * 20
    score += stats['zero_step_count'] * 0.5
    score += stats['second_difference_l1'] * 0.02
    return score


def nibble_stats(payload: bytes, high_first: bool) -> dict:
    nibbles = []
    for b in payload:
        hi, lo = (b >> 4) & 0xF, b & 0xF
        nibbles.extend((hi, lo) if high_first else (lo, hi))
    hist = [0]*16
    for n in nibbles: hist[n] += 1
    groups = [nibbles[i:i+16] for i in range(0, len(nibbles), 16)]
    return {
        'nibbles': len(nibbles),
        'groups16': len(groups),
        'histogram_0_to_15': hist,
        'zero_fraction': hist[0]/len(nibbles) if nibbles else None,
        'group_sum_min': min((sum(g) for g in groups), default=None),
        'group_sum_max': max((sum(g) for g in groups), default=None),
        'group_sum_mean': (sum(sum(g) for g in groups)/len(groups)) if groups else None,
    }


def find_gamma_coarse_candidates(data: bytes, max_candidates: int = 50) -> list[dict]:
    out = []
    count = 256
    byte_len = count*2
    # 2-byte alignment is the natural uint16 case. Sliding windows are heavily
    # overlapping, so retain only local starts that score well and deduplicate later.
    for endian in ('le','be'):
        fmt = ('<' if endian=='le' else '>') + f'{count}H'
        for off in range(0, len(data)-byte_len+1, 2):
            vals = list(struct.unpack_from(fmt, data, off))
            st = gamma_coarse_stats(vals)
            score = gamma_score(st)
            if score >= 1e8:
                continue
            if st['first'] > 64 or st['last'] < 900 or st['unique'] < 100:
                continue
            out.append({
                'offset': off, 'offset_hex': hex(off), 'endian': endian,
                'score': score, 'sha256': sha256(data[off:off+byte_len]),
                'stats': st,
            })
    out.sort(key=lambda x:(x['score'],x['offset']))
    # Suppress sliding-window duplicates within one 512-byte candidate region.
    kept=[]
    for c in out:
        if any(c['endian']==k['endian'] and abs(c['offset']-k['offset']) < 256 for k in kept):
            continue
        kept.append(c)
        if len(kept)>=max_candidates: break
    return kept


def companion_candidates(data: bytes, coarse: dict) -> list[dict]:
    """Describe 2048-byte regions at common structural positions around coarse LUT."""
    off=coarse['offset']; coarse_len=512; comp_len=2048
    positions={
        'immediately_before': off-comp_len,
        'immediately_after': off+coarse_len,
        'after_16byte_align': ((off+coarse_len+15)//16)*16,
        'before_16byte_align': ((off-comp_len)//16)*16,
    }
    out=[]; seen=set()
    for label,p in positions.items():
        if p in seen or p<0 or p+comp_len>len(data): continue
        seen.add(p)
        payload=data[p:p+comp_len]
        out.append({
            'label':label,'offset':p,'offset_hex':hex(p),'sha256':sha256(payload),
            'high_nibble_first':nibble_stats(payload,True),
            'low_nibble_first':nibble_stats(payload,False),
        })
    return out


def probe_file(path: Path, out_dir: Path | None) -> dict:
    data=path.read_bytes()
    tone=find_tone_candidates(data)
    gamma=find_gamma_coarse_candidates(data)
    for g in gamma:
        g['companion_candidates']=companion_candidates(data,g)

    exact_tone=[x for x in tone if x['exact_recorded_range_match']]
    result={
        'file':path.name,'size':len(data),'sha256':sha256(data),
        'tone':{
            'unity_run_count_le':len(find_unity_runs(data,'le')),
            'unity_run_count_be':len(find_unity_runs(data,'be')),
            'exact_candidate_count':len(exact_tone),
            'best_candidates':tone[:20],
        },
        'gamma':{
            'coarse_candidate_count_retained':len(gamma),
            'best_candidates':gamma[:20],
        },
    }
    if out_dir and exact_tone:
        csv_path=out_dir/f'{path.name}.tone_exact.csv'
        write_tone_csv(csv_path,data,exact_tone[0])
        result['tone']['derived_csv']=csv_path.name
        result['tone']['derived_csv_sha256']=sha256(csv_path.read_bytes())
    return result


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('files',nargs='+',type=Path)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--derived-dir',type=Path)
    args=ap.parse_args()
    if args.derived_dir: args.derived_dir.mkdir(parents=True,exist_ok=True)
    result={
        'schema':'m11camera.r2.extracted_asset_probe.v1',
        'recorded_constraints':{
            'tone_states':TONE_STATES,
            'tone_samples_per_state':TONE_SAMPLES,
            'tone_q12_unity':4096,
            'tone_expected_ranges':{str(k):list(v) for k,v in TONE_EXPECTED_RANGES.items()},
            'gamma_coarse_nodes':256,
            'gamma_companion_bytes':2048,
            'gamma_input_bits':12,
            'gamma_output_bits':10,
        },
        'files':[],
    }
    for p in args.files:
        item=probe_file(p,args.derived_dir)
        result['files'].append(item)
        print(f"{p.name}: {item['size']} bytes")
        print(f"  tone exact={item['tone']['exact_candidate_count']} best_error=" +
              (str(item['tone']['best_candidates'][0]['range_error_l1']) if item['tone']['best_candidates'] else 'n/a'))
        print(f"  gamma coarse retained={item['gamma']['coarse_candidate_count_retained']}" +
              (f" best_score={item['gamma']['best_candidates'][0]['score']:.3f}" if item['gamma']['best_candidates'] else ''))
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__': main()
