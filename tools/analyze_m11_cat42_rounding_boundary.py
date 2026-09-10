#!/usr/bin/env python3
"""Quantify the remaining Cat42 per-pixel integer arithmetic ambiguity.

The Cat42 map generator establishes Q3 slope codes exactly and the Leica M11
KY=8 endpoint has now been closed to luminance/Y by the separate endpoint
semantics proof. This tool does NOT select the remaining hardware integer
convention. It enumerates plausible local-coordinate, border-selection and
signed shift/rounding conventions over the full 10-bit Y reference domain for
every creative state, then reports how far their generated CSY scale codes can
differ.

No image fitting and no renderer changes are performed.
"""
from __future__ import annotations

import argparse, hashlib, json, math
from itertools import product
from pathlib import Path

from analyze_m11_cat42_csp_arithmetic import decode_cat42
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA


def div8(v: int, mode: str) -> int:
    if mode == 'arith_shift':
        return v >> 3
    if mode == 'toward_zero':
        return math.trunc(v / 8)
    if mode == 'nearest_away':
        a=abs(v); q=(a+4)//8
        return q if v>=0 else -q
    if mode == 'nearest_even':
        return int(round(v/8.0))
    raise ValueError(mode)


def segment_for(x: int, b: list[int], border_mode: str) -> int:
    b0,b1,b2=b
    if border_mode == 'right_open':
        if x < b0: return 0
        if x < b1: return 1
        if x < b2: return 2
        return 3
    if border_mode == 'left_closed_at_border':
        # Boundary code belongs to the lower-index segment.
        if x <= b0: return 0
        if x <= b1: return 1
        if x <= b2: return 2
        return 3
    raise ValueError(border_mode)


def code_at(x: int, o: list[int], g: list[int], b: list[int], *,
            border_mode: str, origin_mode: str, rounding: str, clamp: bool) -> int:
    s=segment_for(x,b,border_mode)
    starts=[0,b[0],b[1],b[2]]
    origin=starts[s]
    if origin_mode == 'segment_start':
        coord=x-origin
    elif origin_mode == 'segment_start_plus1':
        coord=x-origin+1
    elif origin_mode == 'segment_start_minus1':
        coord=x-origin-1
    else:
        raise ValueError(origin_mode)
    y=o[s]+div8(g[s]*coord,rounding)
    return max(0,min(1023,y)) if clamp else y


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True); ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); dig=hashlib.sha256(data).hexdigest()
    if dig != EXPECTED_UNPACKED_SHA: raise ValueError(f'unexpected SHA {dig}')
    rows=[r for r in decode_cat42(data) if -3 <= r.state <= 3]
    if any(r.csyky != 8 for r in rows):
        raise AssertionError('creative Cat42 KY no longer fixed at 8')

    variants=[]
    for bm,om,rd,cl in product(
        ('right_open','left_closed_at_border'),
        ('segment_start','segment_start_plus1','segment_start_minus1'),
        ('arith_shift','toward_zero','nearest_away','nearest_even'),
        (False,True),
    ):
        name=f'{bm}|{om}|{rd}|clamp={int(cl)}'
        vals={}
        for r in rows:
            o=list(r.offset); g=list(r.gain); b=list(r.border)
            vals[r.state]=[code_at(x,o,g,b,border_mode=bm,origin_mode=om,rounding=rd,clamp=cl) for x in range(1024)]
        variants.append({'name':name,'border_mode':bm,'origin_mode':om,'rounding':rd,'clamp':cl,'values':vals})

    baseline=next(v for v in variants if v['border_mode']=='right_open' and v['origin_mode']=='segment_start' and v['rounding']=='arith_shift' and not v['clamp'])
    comparisons=[]
    for v in variants:
        diffs=[]; nonzero=0; boundary_nonzero=0
        for r in rows:
            state=r.state; b=set(r.border)
            for x,(aa,bb) in enumerate(zip(baseline['values'][state],v['values'][state])):
                d=bb-aa; diffs.append(d)
                if d:
                    nonzero += 1
                    if x in b: boundary_nonzero += 1
        comparisons.append({
            'name':v['name'],
            'max_abs_code_diff':max(abs(x) for x in diffs),
            'mean_abs_code_diff':sum(abs(x) for x in diffs)/len(diffs),
            'nonzero_points':nonzero,
            'nonzero_pct':100.0*nonzero/len(diffs),
            'boundary_nonzero_points':boundary_nonzero,
        })
    comparisons.sort(key=lambda x:(x['max_abs_code_diff'],x['mean_abs_code_diff'],x['nonzero_points']))

    global_max_span=0; global_span_points=0
    state_summaries=[]
    for r in rows:
        spans=[]
        for x in range(1024):
            vv=[v['values'][r.state][x] for v in variants]
            span=max(vv)-min(vv); spans.append(span)
            global_max_span=max(global_max_span,span)
            if span: global_span_points += 1
        state_summaries.append({
            'state':r.state,
            'max_variant_span_codes':max(spans),
            'mean_variant_span_codes':sum(spans)/len(spans),
            'nonzero_span_points':sum(1 for x in spans if x),
            'nonzero_span_pct':100.0*sum(1 for x in spans if x)/len(spans),
            'at_borders':{str(x):{'min':min(v['values'][r.state][x] for v in variants),'max':max(v['values'][r.state][x] for v in variants)} for x in r.border},
        })
    locs=[]
    for r in rows:
        for x in range(1024):
            vv=[v['values'][r.state][x] for v in variants]
            if max(vv)-min(vv)==global_max_span:
                locs.append({'state':r.state,'x':x,'min':min(vv),'max':max(vv)})

    # Restrict to the structurally preferred local origin. This isolates the
    # unresolved border/rounding/clip ambiguity from deliberate ±1 origin
    # stress probes.
    conventional=[v for v in variants if v['origin_mode']=='segment_start']
    conv_states=[]; conv_global=0
    for r in rows:
        spans=[]
        for x in range(1024):
            vv=[v['values'][r.state][x] for v in conventional]
            spans.append(max(vv)-min(vv))
        conv_global=max(conv_global,max(spans))
        conv_states.append({'state':r.state,'max_span_codes':max(spans),'mean_span_codes':sum(spans)/1024,
                            'nonzero_points':sum(1 for z in spans if z)})

    rep={
        'schema':'m11camera.research.cat42_rounding_boundary.v2',
        'sha256':dig,
        'reference_axis':'luminance/Y (KY=8 endpoint closed by separate endpoint-semantics proof)',
        'baseline':baseline['name'],
        'variant_count':len(variants),
        'comparisons_to_baseline':comparisons,
        'all_variant_envelope':{'global_max_span_codes':global_max_span,'max_locations_first100':locs[:100],'states':state_summaries},
        'conventional_segment_start_envelope':{'global_max_span_codes':conv_global,'states':conv_states},
        'code_to_scale_note':'If CSYOF code is interpreted as code/512, one code equals 1/512 = 0.001953125 scale.',
        'evidence_boundary':{
            'ky8_endpoint':'closed_to_luminance_Y_for_Leica_M11',
            'q3_generator':'established_from_28_of_28_gain_codes',
            'hardware_rounding':'open',
            'hardware_border_rule':'open',
            'hardware_origin_off_by_one':'open_but_segment_start_is_structurally_preferred',
            'hardware_clip':'open',
        },
    }

    lines=['# M11-P Cat42 rounding / boundary ambiguity sweep','',
           f'- exact SHA-256: `{dig}`','- reference axis: **luminance/Y** (`KY=8` endpoint closed independently)',f'- variants enumerated: `{len(variants)}`',
           f'- baseline: `{baseline["name"]}`','',
           'One CSY scale code corresponds to `1/512 = 0.001953125` if direct code/512 decoding is used.','',
           '## Conventional local-origin envelope','',
           f'- maximum span across border mode × rounding × clamp with `coord=x-segment_start`: **{conv_global} code(s)**','',
           '| state | max span | mean span | affected reference codes |','|---:|---:|---:|---:|']
    for x in conv_states:
        lines.append(f"| {x['state']:+d} | {x['max_span_codes']} | {x['mean_span_codes']:.6f} | {x['nonzero_points']} / 1024 |")
    lines += ['', '## Full stress envelope including ±1 local-origin probes','',
              f'- maximum span across all variants: **{global_max_span} code(s)**','',
              '| state | max span | mean span | affected codes |','|---:|---:|---:|---:|']
    for x in state_summaries:
        lines.append(f"| {x['state']:+d} | {x['max_variant_span_codes']} | {x['mean_variant_span_codes']:.6f} | {x['nonzero_span_points']} / 1024 |")
    lines += ['', '## Closest alternatives to arithmetic-shift/right-open baseline','']
    for x in comparisons[:16]:
        lines.append(f"- `{x['name']}`: max `{x['max_abs_code_diff']}` code, mean `{x['mean_abs_code_diff']:.6f}`, changed `{x['nonzero_points']}` points ({x['nonzero_pct']:.3f}%), boundary changes `{x['boundary_nonzero_points']}`")
    lines += ['', '## Evidence boundary','',
              'This sweep quantifies the remaining integer implementation ambiguity; it does not identify the hardware convention. The Y endpoint and Q3 generator are independently closed, while exact border ownership and signed rounding remain open.', '']
    a.json.parent.mkdir(parents=True,exist_ok=True); a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(rep,indent=2)+'\n'); a.markdown.write_text('\n'.join(lines)+'\n')
    print(a.markdown)

if __name__=='__main__': main()
