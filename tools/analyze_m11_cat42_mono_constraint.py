#!/usr/bin/env python3
"""Sharpen M11-P Category-42 CSP coefficient constraints using the mono map.

This is a derived arithmetic diagnostic. It intentionally separates:
1. the exact creative-state *map generator* relationship, from
2. possible Milbeaut *hardware coefficient* encodings.

It does not assume CSYKY endpoint direction, chroma magnitude, or the exact
piecewise datapath. In particular, an exact +1 generator fit is not promoted
as a +1 hardware coefficient rule because Leica's enabled monochrome record
uses zero CSYOF and zero CSYGA throughout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from analyze_m11_cat42_csp_arithmetic import decode_cat42, signed_shift
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA


def q3_envelope(row) -> dict:
    """Evaluate the current local-Q3 geometry without claiming it is hardware."""
    starts = (0, row.border[0], row.border[1], row.border[2])
    ends = (row.border[0], row.border[1], row.border[2], 1023)
    segs = []
    for i in range(4):
        coord = ends[i] - starts[i]
        raw = row.offset[i] + row.gain[i] * coord / 8.0
        floor_v = row.offset[i] + signed_shift(row.gain[i] * coord, 3, "floor")
        segs.append(
            {
                "segment": i,
                "start_x": starts[i],
                "end_x": ends[i],
                "start_code": row.offset[i],
                "gain_code": row.gain[i],
                "q3_unrounded_end_code": raw,
                "q3_floor_end_code": floor_v,
                "next_offset_code": row.offset[i + 1] if i < 3 else None,
                "next_offset_residual_unrounded": (
                    raw - row.offset[i + 1] if i < 3 else None
                ),
            }
        )
    return {
        "state": row.state,
        "segments": segs,
        "last_end_minus_common_offset0_unrounded": segs[-1]["q3_unrounded_end_code"] - row.offset[0],
        "last_end_minus_common_offset0_floor": segs[-1]["q3_floor_end_code"] - row.offset[0],
    }


def report(rows) -> dict:
    creative = [r for r in rows if -3 <= r.state <= 3]
    mono = next((r for r in rows if r.state == 10), None)
    if len(creative) != 7 or mono is None:
        raise ValueError("expected creative states -3..+3 and monochrome state 10")

    intended = []
    for r in creative:
        target = 1.15 + 0.15 * r.state
        plateau = r.offset[1]
        direct = plateau / 512.0
        plus1 = (plateau + 1) / 512.0
        intended.append(
            {
                "state": r.state,
                "target": target,
                "plateau_code": plateau,
                "direct_code_over_512": direct,
                "direct_error": direct - target,
                "plus1_code_over_512": plus1,
                "plus1_error": plus1 - target,
                "plus1_equals_rounded_target_q9": plateau + 1 == int(math.floor(target * 512 + 0.5)),
            }
        )

    mono_zero = {
        "state": mono.state,
        "csy_enable": mono.csy_enable,
        "csyky": mono.csyky,
        "csytbl": mono.csytbl,
        "offset": list(mono.offset),
        "gain": list(mono.gain),
        "border": list(mono.border),
        "all_offsets_zero": all(x == 0 for x in mono.offset),
        "all_gains_zero": all(x == 0 for x in mono.gain),
        "all_other_post_border_controls_zero": all(
            x == 0
            for x in (
                mono.y_rev,
                mono.c_rev,
                mono.c_fixed_enable,
                mono.cb_fixed,
                mono.cr_fixed,
                mono.y_offset,
                mono.cb_offset,
                mono.cr_offset,
            )
        ),
        "interpretation": (
            "Leica deliberately uses an enabled CSP record (EN=1, KY=8, TBL=0) with "
            "CSYOF=0 and CSYGA=0 for the monochrome state. Therefore zero must remain a "
            "first-class zero/suppression code somewhere in the effective hardware path; "
            "blindly treating every CSYOF code as (code+1)/512 would leave a nonzero "
            "1/512 coefficient and is not justified by the creative ladder alone. A "
            "special zero rule or another internal encoding remains possible until the "
            "hardware equation is recovered."
        ),
    }

    envelopes = [q3_envelope(r) for r in creative]
    last = [e["last_end_minus_common_offset0_unrounded"] for e in envelopes]

    return {
        "schema": "m11camera.research.cat42_mono_constraint.v1",
        "evidence_boundary": {
            "creative_plus1_relation": "exact_map_generator_constraint",
            "plus1_is_hardware_coefficient_rule": False,
            "direct_code_over_512_is_hardware_rule": "plausible_not_proven",
            "mono_zero_is_primary_map_evidence": True,
            "q3_local_envelope_is_hardware_equation": False,
            "csyky_endpoint_direction": "open",
            "chroma_reference_magnitude": "open",
        },
        "monochrome_zero_constraint": mono_zero,
        "creative_coefficient_comparison": {
            "rows": intended,
            "plus1_matches_rounded_target_all_7": all(x["plus1_equals_rounded_target_q9"] for x in intended),
            "max_abs_direct_error": max(abs(x["direct_error"]) for x in intended),
            "max_abs_plus1_error": max(abs(x["plus1_error"]) for x in intended),
            "interpretation": (
                "The +1 relation is exact against the apparent 0.15-step creative target "
                "ladder, so it is strong evidence about how Leica's stored map values were "
                "generated/quantized. The enabled all-zero monochrome record prevents us "
                "from promoting that +1 to a universal hardware decode. Direct code/512 "
                "is mono-compatible and within one to two codes of the apparent creative "
                "targets, but remains a hardware hypothesis."
            ),
        },
        "local_q3_envelope_constraint": {
            "rows": envelopes,
            "last_wing_minus_offset0_unrounded_min": min(last),
            "last_wing_minus_offset0_unrounded_max": max(last),
            "interpretation": (
                "Under the current local-Q3 diagnostic, the final high-reference wing "
                "returns close to the common low-reference offset0=258 across all seven "
                "creative states. Together with BD0+BD2≈1023 this is strong evidence that "
                "the stored parameters describe a roughly symmetric four-segment envelope, "
                "not a global saturation multiplier. It is still not proof of Q3 or the "
                "hardware border convention."
            ),
        },
    }


def markdown(rep: dict) -> str:
    m = rep["monochrome_zero_constraint"]
    c = rep["creative_coefficient_comparison"]
    e = rep["local_q3_envelope_constraint"]
    lines = [
        "# M11-P Category-42 monochrome/coefficient constraint",
        "",
        "This report separates exact stored-map relationships from unresolved Milbeaut hardware arithmetic.",
        "",
        "## Monochrome zero constraint",
        "",
        f"- state: `{m['state']}`",
        f"- EN/KY/TBL: `{m['csy_enable']}/{m['csyky']}/{m['csytbl']}`",
        f"- CSYOF: `{m['offset']}`",
        f"- CSYGA: `{m['gain']}`",
        f"- CSYBD: `{m['border']}`",
        f"- all CSYOF zero: **{m['all_offsets_zero']}**",
        f"- all CSYGA zero: **{m['all_gains_zero']}**",
        "",
        m["interpretation"],
        "",
        "## Creative plateau encoding comparison",
        "",
        "| state | target | code | code/512 | error | (code+1)/512 | error | +1 exact rounded-Q9 target |",
        "|---:|---:|---:|---:|---:|---:|---:|:---:|",
    ]
    for x in c["rows"]:
        lines.append(
            f"| {x['state']:+d} | {x['target']:.2f} | {x['plateau_code']} | "
            f"{x['direct_code_over_512']:.9f} | {x['direct_error']:+.9f} | "
            f"{x['plus1_code_over_512']:.9f} | {x['plus1_error']:+.9f} | "
            f"{x['plus1_equals_rounded_target_q9']} |"
        )
    lines += [
        "",
        c["interpretation"],
        "",
        "## Local-Q3 envelope diagnostic",
        "",
        "| state | segment-0 end | plateau | segment-2 end | segment-3 end @1023 | end-offset0 |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in e["rows"]:
        s = row["segments"]
        lines.append(
            f"| {row['state']:+d} | {s[0]['q3_unrounded_end_code']:.3f} | "
            f"{s[1]['start_code']} | {s[2]['q3_unrounded_end_code']:.3f} | "
            f"{s[3]['q3_unrounded_end_code']:.3f} | "
            f"{row['last_end_minus_common_offset0_unrounded']:+.3f} |"
        )
    lines += [
        "",
        e["interpretation"],
        "",
        "## Updated evidence boundary",
        "",
        "- `(plateau+1) == round(target*512)`: **exact stored-map/generator constraint**.",
        "- `(CSYOF+1)/512` as universal hardware coefficient: **do not promote**.",
        "- `CSYOF/512`: **plausible and mono-compatible, but not proven**.",
        "- local Q3 segment arithmetic: **best current geometric hypothesis, not proven**.",
        "- CSYKY endpoint direction and chroma reference metric: **still open**.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--markdown", type=Path, required=True)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    rep = report(decode_cat42(data))
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(rep, indent=2) + "\n")
    args.markdown.write_text(markdown(rep) + "\n")
    print(args.markdown)


if __name__ == "__main__":
    main()
