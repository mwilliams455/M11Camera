#!/usr/bin/env python3
"""Quantify Y-vs-chroma interpretations of Leica M11-P Category-42 maps.

This is an endpoint-discrimination analysis, not a vendor-manual substitute.
It uses only exact firmware tables plus already-established Q3 local-segment
geometry. The test asks which endpoint interpretation makes the saturation-state
family structurally coherent without introducing chroma-sign or near-neutral
pathologies.

Evidence considered:
  * common ~0.5x scale at both 10-bit axis endpoints;
  * low-luminance knee rises and highlight knee falls as requested saturation
    increases, the expected protection envelope when midtone chroma gain rises;
  * a magnitude-C interpretation applies the common ~0.5x endpoint at zero
    chroma, i.e. strongest attenuation to nearly neutral colours;
  * a signed-C interpretation centered at code 512 yields unequal gains for
    equal |C| on opposite sides of neutral, creating sign/hue-dependent gain.

The script does not claim the undocumented hardware mixing formula. It may
promote KY=8=>Y only as a constrained project interpretation when all numerical
checks pass; the exact CSYKY interpolation for values 1..7 remains unknown.
"""
from __future__ import annotations

import argparse, hashlib, json, math
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA
from analyze_m11_cat42_csp_arithmetic import load_cat42_states

STATES = [-3,-2,-1,0,1,2,3]


def arshift_q3(prod: int) -> int:
    return prod >> 3


def curve_code(x: int, offsets, gains, borders) -> int:
    # Canonical local Q3 diagnostic arithmetic. Exact border ownership affects
    # only isolated boundary samples and was independently bounded elsewhere.
    if x < borders[0]:
        seg, start = 0, 0
    elif x < borders[1]:
        seg, start = 1, borders[0]
    elif x < borders[2]:
        seg, start = 2, borders[1]
    else:
        seg, start = 3, borders[2]
    return offsets[seg] + arshift_q3(gains[seg] * (x-start))


def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True);ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args();data=a.unpacked.read_bytes();sha=hashlib.sha256(data).hexdigest()
    if sha!=EXPECTED_UNPACKED_SHA:raise ValueError(sha)
    maps=load_cat42_states(data)
    by={int(m['state']):m for m in maps if int(m['state']) in STATES}
    if sorted(by)!=STATES:raise AssertionError(sorted(by))

    rows=[];signed_rows=[]
    for s in STATES:
        m=by[s];o=m['offsets'];g=m['gains'];b=m['borders']
        vals=[curve_code(x,o,g,b) for x in range(1024)]
        # Chroma-scale convention is independently supported by the state ladder;
        # report both direct /512 and +1/512 plateau forms without claiming the
        # +1 convention for every sample.
        row={
            'state':s,'borders':b,'axis_low_scale':vals[0]/512.0,
            'axis_high_scale':vals[1023]/512.0,
            'neutral_code512_scale':vals[512]/512.0,
            'plateau_code':o[1],'plateau_plus1_scale':(o[1]+1)/512.0,
            'low_knee_pct':100*b[0]/1023.0,
            'highlight_rolloff_pct':100*b[1]/1023.0,
            'outer_high_pct':100*b[2]/1023.0,
        }
        rows.append(row)
        # Signed-chroma hypothesis: 10-bit neutral is 512. Compare equal excursions
        # around neutral wherever both codes remain in range.
        diffs=[]
        for d in (32,64,96,128,160,192,224,256,320,384,480):
            lo=512-d;hi=512+d
            if lo>=0 and hi<=1023:
                diffs.append({'d':d,'low_code':vals[lo],'high_code':vals[hi],'abs_delta':abs(vals[lo]-vals[hi])})
        signed_rows.append({'state':s,'pairs':diffs,'max_sign_asym_code':max(x['abs_delta'] for x in diffs),'mean_sign_asym_code':sum(x['abs_delta'] for x in diffs)/len(diffs)})

    # Hard structural checks that do not depend on subjective image judgement.
    low=[r['borders'][0] for r in rows];hi_start=[r['borders'][1] for r in rows]
    endpoint_low=[round(r['axis_low_scale'],6) for r in rows]
    endpoint_high=[round(r['axis_high_scale'],6) for r in rows]
    checks={
        'low_knee_monotonic_up_with_saturation': all(low[i]<low[i+1] for i in range(6)),
        'highlight_rolloff_monotonic_down_with_saturation': all(hi_start[i]>hi_start[i+1] for i in range(6)),
        'common_low_endpoint_code': len({curve_code(0,by[s]['offsets'],by[s]['gains'],by[s]['borders']) for s in STATES})==1,
        'common_high_endpoint_near_258': max(abs(curve_code(1023,by[s]['offsets'],by[s]['gains'],by[s]['borders'])-258) for s in STATES)<=3,
        'signed_chroma_material_asymmetry_exists': max(r['max_sign_asym_code'] for r in signed_rows)>=32,
        'magnitude_zero_would_use_common_half_scale': all(abs(r['axis_low_scale']-258/512)<1e-9 for r in rows),
    }
    if not all(checks.values()):raise AssertionError(checks)

    report={'schema':'m11camera.research.cat42_endpoint_semantics.v1','sha256':sha,'rows':rows,'signed_chroma':signed_rows,'checks':checks,
            'interpretation':{
                'promote':'KY=8 is treated as the luminance/Y endpoint for the Leica M11 Cat42 path',
                'basis':'exact Leica table geometry + Socionext CSYKY naming/API + all-state KY=8 + saturation dependency; chroma endpoint interpretations create structural pathologies',
                'not_claimed':'general CSYKY interpolation formula for hardware values 1..7'},
            'boundary':'Endpoint closure is a constrained engineering inference, not a verbatim Socionext equation. Exact border ownership/rounding remains separately bounded to <= isolated/sub-code photographic impact.'}
    lines=['# M11-P Category-42 endpoint semantics','',f'- SHA-256: `{sha}`','- result: **PASS**','', '## Luminance-envelope geometry','', '| sat | low knee | highlight roll-off | outer high | axis 0 scale | axis 1023 scale | plateau (+1)/512 |','|---:|---:|---:|---:|---:|---:|---:|']
    for r in rows:
        lines.append(f"| {r['state']:+d} | {r['low_knee_pct']:.1f}% | {r['highlight_rolloff_pct']:.1f}% | {r['outer_high_pct']:.1f}% | {r['axis_low_scale']:.3f}x | {r['axis_high_scale']:.3f}x | {r['plateau_plus1_scale']:.3f}x |")
    lines += ['','As requested saturation rises, the low-Y protection knee moves monotonically upward while the high-Y roll-off starts monotonically earlier. Both 10-bit endpoints return to the same ~0.5x chroma scale. This is a coherent luminance-dependent saturation-protection family.','', '## Competing chroma-reference interpretations','']
    lines += ['- **Magnitude C, zero at code 0:** every state would apply ~0.5x gain to the least-chromatic pixels before rising toward the requested saturation plateau. That is structurally opposite to a normal saturation control and makes the special low-axis wing target near-neutral colours rather than shadows.','- **Signed C, neutral at code 512:** equal-magnitude excursions about neutral receive unequal curve gains; the asymmetry becomes large in stronger saturation states. With one common curve for both colour-difference channels this implies sign/hue-dependent saturation behavior.','', '| sat | max equal-|C| sign asymmetry | mean asymmetry |','|---:|---:|---:|']
    for r in signed_rows:lines.append(f"| {r['state']:+d} | {r['max_sign_asym_code']} codes | {r['mean_sign_asym_code']:.1f} codes |")
    lines += ['','## Project conclusion','', '**Promote for the Leica M11 path:** `CSYKY=8` is the luminance/Y endpoint.','', 'This is supported jointly by Socionext naming/API (`KY`, 0..8 luminance/chroma mix), Leica fixing KY=8 in every Cat42 state, the ISO+saturation selector semantics, and the exact all-state curve geometry. The general hardware interpolation equation for KY values 1..7 is still undocumented and is not needed by the Leica maps.','', '## Evidence boundary','',report['boundary'],'']
    a.json.parent.mkdir(parents=True,exist_ok=True);a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(report,indent=2)+'\n');a.markdown.write_text('\n'.join(lines)+'\n');print(a.markdown)
if __name__=='__main__':main()
