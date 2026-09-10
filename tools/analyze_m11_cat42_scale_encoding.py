#!/usr/bin/env python3
"""Constrain Cat42 CSY output-code scaling for the Leica M11 path.

This is a firmware-side engineering closure, not a recovered Socionext pixel
formula.  It combines three primary-image facts:

1. Category 42 is the sole R2YS family selected by saturation (flag 0x200).
2. Its +10 monochrome record leaves CSP enabled (EN=1, KY=8) but programs an
   identically-zero four-segment CSY curve.
3. The creative plateau codes span 357..818 across states -3..+3.

For a fixed-point multiplicative chroma scale with a power-of-two denominator,
Q9 (/512) is the only nearby binary interpretation whose creative family
straddles unity: Q8 makes every state >1, while Q10 makes every state <1.
Within Q9, direct code/512 preserves the active monochrome zero.  (code+1)/512
matches the aesthetically compact creative ladder more closely but requires an
otherwise-unseen special case to map stored code 0 back to exact zero.

The report intentionally leaves the general hardware equation and any possible
undocumented zero special-case outside the proof boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analyze_m11_cat42_csp_arithmetic import decode_cat42
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, parse_r2y

SAT_FLAG = 0x200
STATES = [-3, -2, -1, 0, 1, 2, 3]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--markdown", type=Path, required=True)
    a = ap.parse_args()

    data = a.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    _, _, _, descriptors = parse_r2y(data)
    sat = [d for d in descriptors if d["flags"] & SAT_FLAG]
    sat_categories = sorted({d["category"] for d in sat})
    if sat_categories != [42] or len(sat) != 8:
        raise AssertionError(
            f"saturation fanout changed: categories={sat_categories} descriptors={len(sat)}"
        )

    maps = {m.state: m for m in decode_cat42(data)}
    if sorted(maps) != STATES + [10]:
        raise AssertionError(f"unexpected Cat42 states: {sorted(maps)}")
    if any(maps[s].csy_enable != 1 or maps[s].csyky != 8 or maps[s].csytbl != 0 for s in maps):
        raise AssertionError("Cat42 control invariants changed")

    mono = maps[10]
    if mono.offset != (0, 0, 0, 0) or mono.gain != (0, 0, 0, 0):
        raise AssertionError("+10 Cat42 curve is no longer identically zero")

    plateau = {s: maps[s].offset[1] for s in STATES}
    if any(maps[s].offset[1] != maps[s].offset[2] for s in STATES):
        raise AssertionError("creative plateau offsets are no longer equal")

    binary_candidates = []
    for q in (8, 9, 10):
        den = 1 << q
        vals = {s: plateau[s] / den for s in STATES}
        binary_candidates.append({
            "fractional_bits": q,
            "denominator": den,
            "direct_scales": vals,
            "minimum": min(vals.values()),
            "state0": vals[0],
            "maximum": max(vals.values()),
            "states_below_unity": [s for s, v in vals.items() if v < 1.0],
            "states_above_unity": [s for s, v in vals.items() if v > 1.0],
            "straddles_unity": min(vals.values()) < 1.0 < max(vals.values()),
        })

    q9 = next(x for x in binary_candidates if x["fractional_bits"] == 9)
    if not q9["straddles_unity"]:
        raise AssertionError("Q9 creative family no longer straddles unity")
    if any(x["straddles_unity"] for x in binary_candidates if x["fractional_bits"] != 9):
        raise AssertionError("another nearby binary denominator now also straddles unity")

    direct = []
    plus1 = []
    nominal = []
    for s in STATES:
        code = plateau[s]
        # The compact decimal ladder is a descriptor of the recovered sequence,
        # not an independently assumed camera formula.
        target = 1.15 + 0.15 * s
        nominal.append({"state": s, "target": target})
        direct.append({
            "state": s,
            "code": code,
            "scale": code / 512.0,
            "delta_from_compact_ladder": code / 512.0 - target,
        })
        plus1.append({
            "state": s,
            "code": code,
            "scale": (code + 1) / 512.0,
            "delta_from_compact_ladder": (code + 1) / 512.0 - target,
        })

    result = {
        "schema": "m11camera.research.cat42_scale_encoding.v1",
        "sha256": digest,
        "saturation_fanout": {
            "descriptor_count": len(sat),
            "categories": sat_categories,
            "states": sorted(maps),
        },
        "active_monochrome_zero": {
            "state": 10,
            "csy_enable": mono.csy_enable,
            "csyky": mono.csyky,
            "csytbl": mono.csytbl,
            "offsets": list(mono.offset),
            "gains": list(mono.gain),
            "direct_q9_zero_scale": 0.0,
            "plus_one_q9_zero_scale": 1.0 / 512.0,
        },
        "creative_plateau_codes": plateau,
        "binary_denominator_candidates": binary_candidates,
        "direct_q9": direct,
        "plus_one_q9": plus1,
        "engineering_conclusion": {
            "promote_for_m11": "direct CSY output code / 512 (zero-preserving Q9)",
            "why": [
                "Q9 is the only nearby power-of-two denominator whose -3..+3 saturation family straddles unity",
                "stored code 0 remains exact zero in the active +10 monochrome map",
                "Category42 is the sole R2YS saturation-selected family, so no second R2Y saturation block is available to cancel a +1 residual",
                "(code+1)/512 needs an undocumented zero special-case even though it makes the creative decimal ladder slightly neater",
            ],
            "not_claimed": [
                "verbatim Socionext multiplier equation",
                "general behavior for non-Leica KY values 1..7",
                "absence of unrelated downstream monochrome logic outside R2YS",
            ],
        },
        "evidence_boundary": "This closes the renderer's M11 scale-code interpretation at the project's engineering threshold. It does not manufacture missing vendor documentation; future primary hardware documentation can supersede it.",
    }

    lines = [
        "# M11-P Cat42 scale-code constraint", "",
        f"- SHA-256: `{digest}`",
        "- saturation-selected R2YS categories: **[42] only**",
        "- +10 map: **EN=1, KY=8, TBL=0, offsets=0, gains=0**",
        "", "## Nearby binary fixed-point interpretations", "",
        "| format | denominator | -3 | state 0 | +3 | straddles unity |",
        "|---|---:|---:|---:|---:|:---:|",
    ]
    for x in binary_candidates:
        lines.append(
            f"| Q{x['fractional_bits']} | {x['denominator']} | {x['direct_scales'][-3]:.6f} | "
            f"{x['direct_scales'][0]:.6f} | {x['direct_scales'][3]:.6f} | {x['straddles_unity']} |"
        )
    lines += [
        "", "Only **Q9 (/512)** spans attenuation and boost across the recovered -3..+3 saturation family. Q8 makes every creative state greater than unity; Q10 makes every state less than unity.",
        "", "## Q9 direct vs +1", "",
        "| state | code | code/512 | (code+1)/512 | compact ladder |",
        "|---:|---:|---:|---:|---:|",
    ]
    for s in STATES:
        d = next(x for x in direct if x["state"] == s)
        p = next(x for x in plus1 if x["state"] == s)
        lines.append(f"| {s:+d} | {plateau[s]} | {d['scale']:.6f} | {p['scale']:.6f} | {1.15 + 0.15*s:.2f} |")
    lines += [
        "", "The `+1` form makes the compact creative ladder unusually neat, but it maps stored zero to `1/512` rather than zero. Leica's only saturation-selected R2Y family deliberately programs an active, identically-zero Cat42 curve for +10. Direct Q9 preserves that zero without inventing a special case.",
        "", "## Project conclusion", "",
        "**Promote for the M11 renderer:** direct zero-preserving Q9, `CSY scale = code / 512`.",
        "", "This is an engineering closure for the recovered M11 configuration, not a verbatim undocumented Socionext pixel equation. The `plateau+1` identity remains recorded as a likely table-generator/quantization clue.", "",
    ]

    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.markdown.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(result, indent=2) + "\n")
    a.markdown.write_text("\n".join(lines) + "\n")
    print(a.markdown)


if __name__ == "__main__":
    main()
