#!/usr/bin/env python3
"""Quantify Y-vs-chroma interpretations of Leica M11-P Category-42 maps.

This is an endpoint-discrimination analysis, not a vendor-manual substitute.
It uses exact firmware tables plus the already-established Q3 local-segment
geometry. It asks which endpoint interpretation makes the saturation-state
family structurally coherent without chroma-sign or near-neutral pathologies.

The script does not claim the undocumented CSYKY interpolation formula for
values 1..7. It evaluates only the Leica case, where every map fixes KY=8.
"""
from __future__ import annotations

import argparse, hashlib, json
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA
from analyze_m11_cat42_csp_arithmetic import decode_cat42

STATES = [-3, -2, -1, 0, 1, 2, 3]


def curve_code(x: int, offsets, gains, borders) -> int:
    if x < borders[0]:
        seg, start = 0, 0
    elif x < borders[1]:
        seg, start = 1, borders[0]
    elif x < borders[2]:
        seg, start = 2, borders[1]
    else:
        seg, start = 3, borders[2]
    return offsets[seg] + ((gains[seg] * (x - start)) >> 3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('unpacked', type=Path)
    ap.add_argument('--json', type=Path, required=True)
    ap.add_argument('--markdown', type=Path, required=True)
    a = ap.parse_args()

    data = a.unpacked.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_UNPACKED_SHA:
        raise ValueError(sha)

    maps = decode_cat42(data)
    by = {m.state: m for m in maps if m.state in STATES}
    if sorted(by) != STATES:
        raise AssertionError(sorted(by))
    if any(by[s].csyky != 8 for s in STATES):
        raise AssertionError('creative Cat42 KY is no longer fixed at 8')
    if any(by[s].csytbl != 0 for s in STATES):
        raise AssertionError('creative Cat42 TBL is no longer fixed at 0')

    rows, signed_rows = [], []
    for s in STATES:
        m = by[s]
        o, g, b = m.offset, m.gain, m.border
        vals = [curve_code(x, o, g, b) for x in range(1024)]
        rows.append({
            'state': s,
            'borders': list(b),
            'axis_low_code': vals[0],
            'axis_high_code': vals[1023],
            'axis_low_scale': vals[0] / 512.0,
            'axis_high_scale': vals[1023] / 512.0,
            'neutral_code512_scale': vals[512] / 512.0,
            'plateau_code': o[1],
            'plateau_plus1_scale': (o[1] + 1) / 512.0,
            'low_knee_pct': 100.0 * b[0] / 1023.0,
            'highlight_rolloff_pct': 100.0 * b[1] / 1023.0,
            'outer_high_pct': 100.0 * b[2] / 1023.0,
        })
        diffs = []
        for d in (32, 64, 96, 128, 160, 192, 224, 256, 320, 384, 480):
            lo, hi = 512 - d, 512 + d
            if lo >= 0 and hi <= 1023:
                diffs.append({
                    'd': d,
                    'low_code': vals[lo],
                    'high_code': vals[hi],
                    'abs_delta': abs(vals[lo] - vals[hi]),
                })
        signed_rows.append({
            'state': s,
            'pairs': diffs,
            'max_sign_asym_code': max(x['abs_delta'] for x in diffs),
            'mean_sign_asym_code': sum(x['abs_delta'] for x in diffs) / len(diffs),
        })

    low_knees = [by[s].border[0] for s in STATES]
    high_knees = [by[s].border[1] for s in STATES]
    high_endpoint_codes = [r['axis_high_code'] for r in rows]
    checks = {
        'low_knee_monotonic_up_with_saturation': all(low_knees[i] < low_knees[i+1] for i in range(6)),
        'highlight_rolloff_monotonic_down_with_saturation': all(high_knees[i] > high_knees[i+1] for i in range(6)),
        'common_low_endpoint_code_258': all(r['axis_low_code'] == 258 for r in rows),
        # The claim is convergence to half scale, not equality with the stored
        # low-axis offset. Under the independently bounded local-Q3 arithmetic,
        # the high endpoint lands at codes 252..260, i.e. within four codes of
        # exact half scale (256/512 = 0.5x).
        'common_high_endpoint_near_half_scale_256': max(abs(code - 256) for code in high_endpoint_codes) <= 4,
        'signed_chroma_material_asymmetry_exists': max(r['max_sign_asym_code'] for r in signed_rows) >= 32,
        'magnitude_zero_would_use_common_half_scale': all(abs(r['axis_low_scale'] - 258/512) < 1e-12 for r in rows),
    }
    if not all(checks.values()):
        raise AssertionError(checks)

    report = {
        'schema': 'm11camera.research.cat42_endpoint_semantics.v3',
        'sha256': sha,
        'rows': rows,
        'signed_chroma': signed_rows,
        'checks': checks,
        'endpoint_summary': {
            'low_endpoint_code': 258,
            'high_endpoint_min_code': min(high_endpoint_codes),
            'high_endpoint_max_code': max(high_endpoint_codes),
            'exact_half_scale_code': 256,
        },
        'interpretation': {
            'promote_for_m11_path': 'CSYKY=8 is treated as the luminance/Y endpoint',
            'basis': 'Socionext KY naming/API + Leica all-state KY=8 + ISO/saturation selector semantics + exact all-state envelope geometry',
            'not_claimed': 'general CSYKY interpolation equation for hardware values 1..7',
        },
        'boundary': 'This is constrained engineering closure for the Leica KY=8 case, not a verbatim Socionext pixel equation. Exact border ownership/rounding remains separately bounded.',
    }

    lines = [
        '# M11-P Category-42 endpoint semantics', '',
        f'- SHA-256: `{sha}`', '- result: **PASS**',
        '- all creative maps: `KY=8`, `TBL=0`',
        f"- low-axis endpoint: `258` ({258/512.0:.3f}x)",
        f"- high-axis endpoints: `{min(high_endpoint_codes)}..{max(high_endpoint_codes)}` ({min(high_endpoint_codes)/512.0:.3f}x..{max(high_endpoint_codes)/512.0:.3f}x)", '',
        '## Luminance-envelope geometry', '',
        '| sat | low knee | highlight roll-off | outer high | axis 0 scale | axis 1023 scale | plateau (+1)/512 |',
        '|---:|---:|---:|---:|---:|---:|---:|',
    ]
    for r in rows:
        lines.append(
            f"| {r['state']:+d} | {r['low_knee_pct']:.1f}% | {r['highlight_rolloff_pct']:.1f}% | "
            f"{r['outer_high_pct']:.1f}% | {r['axis_low_scale']:.3f}x | {r['axis_high_scale']:.3f}x | "
            f"{r['plateau_plus1_scale']:.3f}x |"
        )
    lines += [
        '',
        'As requested saturation rises, the low-axis protection knee moves monotonically upward while the high-axis roll-off starts monotonically earlier. Both 10-bit endpoints converge on ~0.5x chroma scale. Interpreted as Y, this is a coherent shadow/highlight saturation-protection family.',
        '', '## Competing chroma-reference interpretations', '',
        '- **Magnitude C, zero at code 0:** every state would apply ~0.5x to the least-chromatic pixels before rising toward its requested saturation plateau. That makes the specially shaped low-axis wing target near-neutral colour rather than shadow luminance.',
        '- **Signed C, neutral at code 512:** equal-magnitude excursions around neutral receive unequal scale values; the asymmetry grows materially in stronger saturation states. With one common curve this implies sign/hue-dependent saturation behavior.',
        '', '| sat | max equal-|C| sign asymmetry | mean asymmetry |', '|---:|---:|---:|',
    ]
    for r in signed_rows:
        lines.append(f"| {r['state']:+d} | {r['max_sign_asym_code']} codes | {r['mean_sign_asym_code']:.1f} codes |")
    lines += [
        '', '## Project conclusion', '',
        '**Promote for the Leica M11 path:** `CSYKY=8` is the luminance/Y endpoint.', '',
        'This is jointly supported by Socionext naming/API (`KY`, 0..8 luminance/chroma mix), Leica fixing KY=8 in every Cat42 state, the proven ISO+saturation selection path, and the all-state curve geometry. The general KY=1..7 interpolation remains undocumented and is not exercised by Leica.', '',
        '## Evidence boundary', '', report['boundary'], '',
    ]

    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.markdown.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(report, indent=2) + '\n')
    a.markdown.write_text('\n'.join(lines) + '\n')
    print(a.markdown)


if __name__ == '__main__':
    main()
