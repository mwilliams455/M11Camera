#!/usr/bin/env python3
"""Locate Leica R2YS maps shaped like Milbeaut R2yCtrlYnr and test gain Q-format.

This is a research locator. A structurally compatible 26/28-byte map is not
called YNR unless/until its firmware consumer is traced. The useful question is
whether an independent 4-offset/4-gain/3-border Milbeaut primitive also strongly
selects the same local Q3 arithmetic suggested by Category 42 CSP.
"""
from __future__ import annotations

import argparse, hashlib, json, math, struct
from collections import defaultdict
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y, map_bytes


def decode_candidate(raw: bytes):
    if len(raw) not in (26, 28):
        return None
    # R2yCtrlYnr layout in public Milbeaut API:
    # u16 mode, u16 blend, u16 offset[4], s16 gain[4], u16 border[3].
    vals = struct.unpack('<13H', raw[:26])
    mode, blend = vals[0], vals[1]
    offsets = list(vals[2:6])
    gains = [struct.unpack('<h', struct.pack('<H', x))[0] for x in vals[6:10]]
    borders = list(vals[10:13])
    if mode > 2 or blend > 7:
        return None
    if any(x > 1023 for x in offsets):
        return None
    if any(x < -1024 or x > 1023 for x in gains):
        return None
    if any(x > 1023 for x in borders) or not (borders[0] <= borders[1] <= borders[2]):
        return None
    return {
        'mode': mode, 'blend': blend, 'offsets': offsets, 'gains': gains,
        'borders': borders, 'padding_hex': raw[26:].hex(),
    }


def shift_signed(v: int, q: int, rounding: str) -> int:
    if q == 0:
        return v
    den = 1 << q
    if rounding == 'floor':
        return v // den
    if rounding == 'toward_zero':
        return math.trunc(v / den)
    if rounding == 'nearest_away':
        a = abs(v)
        z = (a + den // 2) // den
        return z if v >= 0 else -z
    raise ValueError(rounding)


def continuity_rank(records):
    ranked=[]
    for anchor in ('local','absolute'):
        for q in range(0,13):
            for delta in (-2,-1,0,1,2):
                for rounding in ('floor','toward_zero','nearest_away'):
                    errs=[]
                    for r in records:
                        o=r['decoded']['offsets']; g=r['decoded']['gains']; b=r['decoded']['borders']
                        starts=(0,b[0],b[1],b[2])
                        for seg in range(3):
                            x=b[seg]+delta
                            coord=x-starts[seg] if anchor=='local' else x
                            pred=o[seg]+shift_signed(g[seg]*coord,q,rounding)
                            errs.append(pred-o[seg+1])
                    if not errs: continue
                    mae=sum(abs(e) for e in errs)/len(errs)
                    rms=math.sqrt(sum(e*e for e in errs)/len(errs))
                    ranked.append({'anchor':anchor,'q':q,'delta':delta,'rounding':rounding,
                                   'mae':mae,'rms':rms,'max_abs':max(abs(e) for e in errs)})
    ranked.sort(key=lambda x:(x['mae'],x['rms'],x['max_abs']))
    return ranked


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True); ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); dig=hashlib.sha256(data).hexdigest()
    if dig != EXPECTED_UNPACKED_SHA: raise ValueError(f'unexpected SHA {dig}')
    base,size,hdr,descs=parse_r2y(data)

    groups=defaultdict(list)
    for d in descs:
        if d['map_size'] not in (26,28): continue
        raw=map_bytes(data,base,d); dec=decode_candidate(raw)
        if dec is None: continue
        groups[d['category']].append({
            'index':d['index'],'flags':d['flags'],'map_size':d['map_size'],
            'map_abs':d['map_offset_abs'],'dependencies':d['dependencies_s32'],
            'decoded':dec,
        })

    results=[]
    for cat,recs in sorted(groups.items()):
        rank=continuity_rank(recs)
        best=rank[0] if rank else None
        q3=next((x for x in rank if x['anchor']=='local' and x['q']==3),None)
        results.append({'category':cat,'count':len(recs),'records':recs,'best':best,'best_local_q3':q3,
                        'top10':rank[:10]})

    rep={'sha256':dig,'r2ys_base':base,'candidate_categories':results,
         'boundary':'structural R2yCtrlYnr compatibility is a locator, not consumer proof'}
    lines=['# M11-P R2yCtrlYnr-shaped map / Q-format probe','',f'- SHA-256: `{dig}`',
           f'- R2YS base: `0x{base:08x}`',f'- structurally compatible categories: `{len(results)}`','']
    for r in results:
        lines += [f"## Category {r['category']}",f"- compatible records: `{r['count']}`",
                  f"- best continuity: `{r['best']}`",f"- best local Q3: `{r['best_local_q3']}`",'',
                  '| deps | map | mode | blend | offsets | gains | borders | pad |',
                  '|---|---:|---:|---:|---|---|---|---|']
        for x in r['records']:
            d=x['decoded']; lines.append(f"| `{x['dependencies']}` | `0x{x['map_abs']:08x}` | {d['mode']} | {d['blend']} | `{d['offsets']}` | `{d['gains']}` | `{d['borders']}` | `{d['padding_hex']}` |")
        lines.append('')
    lines += ['## Evidence boundary','',rep['boundary']+'. A candidate becomes Leica YNR evidence only after a code/consumer trace ties that category to the Milbeaut YNR register programmer.','']
    a.json.parent.mkdir(parents=True,exist_ok=True); a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(rep,indent=2)+'\n'); a.markdown.write_text('\n'.join(lines)+'\n')
    print(a.markdown)

if __name__=='__main__': main()
