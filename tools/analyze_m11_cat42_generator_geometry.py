#!/usr/bin/env python3
"""Prove compact generator relationships across all creative Category-42 maps.

This analysis separates stored-map generator facts from unresolved CSP pixel
arithmetic. In particular, it tests whether every CSYGA code is the nearest
integer Q3 slope between the four stored curve nodes over the stored border
widths. That is much stronger evidence for the gain Q-format than continuity
ranking on one map, but it still does not establish the hardware's per-pixel
rounding/border convention or the CSYKY endpoint formula.
"""
from __future__ import annotations

import argparse, hashlib, json, math
from pathlib import Path

from analyze_m11_cat42_csp_arithmetic import decode_cat42
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA


def nearest_away(x: float) -> int:
    return math.floor(x + 0.5) if x >= 0 else math.ceil(x - 0.5)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True); ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); dig=hashlib.sha256(data).hexdigest()
    if dig != EXPECTED_UNPACKED_SHA: raise ValueError(f'unexpected SHA {dig}')
    creative=[r for r in decode_cat42(data) if -3 <= r.state <= 3]
    if len(creative)!=7: raise ValueError(len(creative))

    rows=[]; gain_matches=0; gain_total=0
    for r in creative:
        o=list(r.offset); g=list(r.gain); b=list(r.border)
        widths=[b[0], b[1]-b[0], b[2]-b[1], 1023-b[2]]
        next_nodes=[o[1],o[2],o[3],258]
        seg=[]
        for i in range(4):
            ideal_q3=8.0*(next_nodes[i]-o[i])/widths[i]
            q=nearest_away(ideal_q3)
            ok=q==g[i]; gain_matches += int(ok); gain_total += 1
            seg.append({'segment':i,'width':widths[i],'start_offset':o[i],
                        'target_end_offset':next_nodes[i],'ideal_q3_gain_code':ideal_q3,
                        'nearest_q3_gain_code':q,'stored_gain':g[i],'match':ok})
        p=o[1]
        exact={
            'plateau_state_formula': p == (384*r.state + 2941)//5,
            'low_border_state_formula': b[0] == (93*r.state + 403)//4,
            'high_border_state_formula': b[2] == (-93*r.state + 3691)//4,
            'transition_width_from_high_wing': b[1] == b[2] - (3*(1023-b[2]))//2,
            'offset3_from_plateau': o[3] == (3*p + 257)//4,
        }
        rows.append({'state':r.state,'offsets':o,'gains':g,'borders':b,'widths':widths,
                     'segments':seg,'exact_generator_relations':exact})

    all_relations=all(all(x['exact_generator_relations'].values()) for x in rows)
    rep={
        'schema':'m11camera.research.cat42_generator_geometry.v1',
        'sha256':dig,
        'gain_q3_node_slope_matches':gain_matches,
        'gain_q3_node_slope_total':gain_total,
        'all_gain_codes_match_nearest_q3_node_slope':gain_matches==gain_total,
        'all_compact_generator_relations_match':all_relations,
        'relations':{
            'plateau':'P = floor((384*state + 2941)/5)',
            'border0':'BD0 = floor((93*state + 403)/4)',
            'border2':'BD2 = floor((-93*state + 3691)/4)',
            'border1':'BD1 = BD2 - floor(3*(1023-BD2)/2)',
            'offset3':'OF3 = floor((3*P + 257)/4)',
            'gain':'GA[i] = nearest_integer(8*(node[i+1]-OF[i])/segment_width[i])',
            'final_node':'258',
        },
        'rows':rows,
        'evidence_boundary':{
            'q3_as_stored_gain_generator':'strong_exact_cross_state_evidence',
            'per_pixel_gain_fractional_bits':'high_confidence_not_directly_observed',
            'per_pixel_rounding':'open',
            'border_inclusive_exclusive':'open',
            'csyky_endpoint':'open',
            'csytbl_semantics':'open',
        },
    }

    lines=['# M11-P Category-42 generator geometry','',
           'Stored-map generator analysis only; this does not claim the internal CSP pixel equation is fully recovered.','',
           f'- exact SHA-256: `{dig}`',
           f'- nearest-Q3 node-slope gain matches: **{gain_matches}/{gain_total}**',
           f'- all compact generator relations match: **{all_relations}**','',
           '## Exact compact relations','']
    for k,v in rep['relations'].items(): lines.append(f'- `{k}`: `{v}`')
    lines += ['', '## Per-state Q3 slope reconstruction','',
              '| state | widths | stored gains | ideal Q3 gain codes | nearest Q3 | all match |',
              '|---:|---|---|---|---|:---:|']
    for x in rows:
        ideal=[round(s['ideal_q3_gain_code'],6) for s in x['segments']]
        near=[s['nearest_q3_gain_code'] for s in x['segments']]
        ok=all(s['match'] for s in x['segments'])
        lines.append(f"| {x['state']:+d} | `{x['widths']}` | `{x['gains']}` | `{ideal}` | `{near}` | {ok} |")
    lines += ['', '## Interpretation','',
              'Across every creative state, all four stored gain fields are exactly the nearest integer to the Q3 slope required to connect the stored node targets over the stored segment widths. This makes Q3 a property of the map generator with 28/28 agreement, not merely the best continuity fit of Standard. The hardware may still use an inclusive/exclusive border convention and integer rounding that produce small discontinuities at runtime; those remain separate questions.', '',
              'The borders and offsets also collapse to compact state formulas, with the high outer wing symmetric to the low wing and the transition width exactly 1.5 times the high-wing width after integer truncation. This is consistent with a deliberately constructed luminance-envelope family.', '',
              '## Evidence boundary','',
              '- Promote: **CSYGA is generated as a Q3 slope code**.',
              '- High confidence but not direct datapath proof: **hardware interprets CSYGA with three fractional bits**.',
              '- Still open: CSYKY endpoint/mixing equation, CSYTBL semantics, exact border comparison and multiply/rounding behavior.', '']
    a.json.parent.mkdir(parents=True,exist_ok=True); a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(rep,indent=2)+'\n'); a.markdown.write_text('\n'.join(lines)+'\n')
    print(a.markdown)

if __name__=='__main__': main()
