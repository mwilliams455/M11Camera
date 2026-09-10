#!/usr/bin/env python3
"""Analyze Leica M11-P Category-42 / Milbeaut CSP arithmetic constraints.

This tool operates only on the verified unpacked M11-P 2.6.1 image and emits
DERIVED metadata. It does not reproduce firmware bytes. The purpose is to use
all creative saturation states together to test fixed-point/segment hypotheses
without fitting a single photograph or a single Standard map.

Important evidence boundary:
- Category 42 -> R2yCtrlCs is a strong structural mapping.
- This analyzer does NOT assume CSYKY endpoint direction or chroma magnitude.
- Continuity scores and compact algebraic fits are diagnostics, not proof that
  hardware implements those exact equations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from dataclasses import dataclass
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, map_bytes, parse_r2y


@dataclass(frozen=True)
class Cat42:
    state: int
    csy_enable: int
    csyky: int
    csytbl: int
    offset: tuple[int, int, int, int]
    gain: tuple[int, int, int, int]
    border: tuple[int, int, int]
    y_rev: int
    c_rev: int
    c_fixed_enable: int
    cb_fixed: int
    cr_fixed: int
    y_offset: int
    cb_offset: int
    cr_offset: int
    map_offset_abs: int
    map_sha256: str


def decode_cat42(unpacked: bytes) -> list[Cat42]:
    base, _, _, descriptors = parse_r2y(unpacked)
    rows: list[Cat42] = []
    for d in descriptors:
        if d["category"] != 42:
            continue
        raw = map_bytes(unpacked, base, d)
        if len(raw) != 44:
            raise ValueError(f"Category-42 map is {len(raw)} bytes, expected 44")
        v = struct.unpack("<22h", raw)
        deps = d["dependencies_s32"]
        if len(deps) < 3:
            raise ValueError("Category-42 descriptor lacks saturation dependency")
        rows.append(
            Cat42(
                state=deps[2],
                csy_enable=v[0],
                csyky=v[1],
                csytbl=v[2],
                offset=tuple(v[3:7]),
                gain=tuple(v[7:11]),
                border=tuple(v[11:14]),
                y_rev=v[14],
                c_rev=v[15],
                c_fixed_enable=v[16],
                cb_fixed=v[17],
                cr_fixed=v[18],
                y_offset=v[19],
                cb_offset=v[20],
                cr_offset=v[21],
                map_offset_abs=d["map_offset_abs"],
                map_sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    rows.sort(key=lambda r: r.state)
    return rows


def signed_shift(value: int, q: int, mode: str) -> int:
    if q == 0:
        return value
    den = 1 << q
    if mode == "floor":
        return value // den
    if mode == "toward_zero":
        return math.trunc(value / den)
    if mode == "nearest_away":
        a = abs(value)
        out = (a + den // 2) // den
        return out if value >= 0 else -out
    raise ValueError(mode)


def continuity_candidates(rows: list[Cat42]) -> list[dict]:
    creative = [r for r in rows if -3 <= r.state <= 3]
    out: list[dict] = []
    # Only test transitions 0->1, 1->2, 2->3. The final segment has no next
    # offset against which to form a continuity residual.
    for anchoring in ("local", "absolute"):
        for q in range(0, 13):
            for boundary_delta in (-2, -1, 0, 1, 2):
                for rounding in ("floor", "toward_zero", "nearest_away"):
                    residuals: list[int] = []
                    detail: list[dict] = []
                    for r in creative:
                        starts = (0, r.border[0], r.border[1], r.border[2])
                        ends = r.border
                        for seg in range(3):
                            x = ends[seg] + boundary_delta
                            coord = x - starts[seg] if anchoring == "local" else x
                            pred = r.offset[seg] + signed_shift(r.gain[seg] * coord, q, rounding)
                            err = pred - r.offset[seg + 1]
                            residuals.append(err)
                            detail.append(
                                {
                                    "state": r.state,
                                    "transition": f"{seg}->{seg+1}",
                                    "pred": pred,
                                    "next_offset": r.offset[seg + 1],
                                    "residual": err,
                                }
                            )
                    mae = sum(abs(x) for x in residuals) / len(residuals)
                    rms = math.sqrt(sum(x * x for x in residuals) / len(residuals))
                    max_abs = max(abs(x) for x in residuals)
                    out.append(
                        {
                            "anchoring": anchoring,
                            "gain_fractional_bits": q,
                            "boundary_delta": boundary_delta,
                            "rounding": rounding,
                            "mae_codes": mae,
                            "rms_codes": rms,
                            "max_abs_codes": max_abs,
                            "detail": detail,
                        }
                    )
    out.sort(key=lambda x: (x["mae_codes"], x["rms_codes"], x["max_abs_codes"]))
    return out


def field_invariants(rows: list[Cat42]) -> dict:
    creative = [r for r in rows if -3 <= r.state <= 3]
    fields = {
        "csy_enable": [r.csy_enable for r in creative],
        "csyky": [r.csyky for r in creative],
        "csytbl": [r.csytbl for r in creative],
        "y_rev": [r.y_rev for r in creative],
        "c_rev": [r.c_rev for r in creative],
        "c_fixed_enable": [r.c_fixed_enable for r in creative],
        "cb_fixed": [r.cb_fixed for r in creative],
        "cr_fixed": [r.cr_fixed for r in creative],
        "y_offset": [r.y_offset for r in creative],
        "cb_offset": [r.cb_offset for r in creative],
        "cr_offset": [r.cr_offset for r in creative],
    }
    return {
        name: {
            "values_by_state_-3_to_+3": vals,
            "constant": len(set(vals)) == 1,
            "constant_value": vals[0] if len(set(vals)) == 1 else None,
        }
        for name, vals in fields.items()
    }


def affine_sequence(values: list[int]) -> dict:
    diffs = [b - a for a, b in zip(values, values[1:])]
    second = [b - a for a, b in zip(diffs, diffs[1:])]
    return {"values": values, "first_differences": diffs, "second_differences": second}


def creative_scale_constraints(creative: list[Cat42]) -> dict:
    # The plateau is offset[1] == offset[2] in all seven creative states.
    # Test the particularly compact Q9 ladder suggested by the recovered codes:
    # state -3..+3 -> 0.70, 0.85, 1.00, 1.15, 1.30, 1.45, 1.60.
    rows = []
    exact = True
    for r in creative:
        plateau = r.offset[1]
        target = 1.15 + 0.15 * r.state
        target_q9 = int(math.floor(target * 512.0 + 0.5))
        match = plateau + 1 == target_q9
        exact = exact and match
        rows.append(
            {
                "state": r.state,
                "plateau_code": plateau,
                "plateau_plus_one": plateau + 1,
                "target_scale": target,
                "round_target_times_512": target_q9,
                "plus_one_matches_target_q9": match,
                "direct_code_over_512": plateau / 512.0,
                "plus_one_over_512": (plateau + 1) / 512.0,
            }
        )

    outer = [
        {
            "state": r.state,
            "border0": r.border[0],
            "border2": r.border[2],
            "sum": r.border[0] + r.border[2],
            "distance_from_1023": r.border[0] + r.border[2] - 1023,
        }
        for r in creative
    ]

    # Search a tiny compact affine/floor family for offset[3] as a function of
    # the plateau. This is descriptive only: exact fit does not prove hardware
    # computes offset[3] at runtime from offset[1].
    compact_o3 = []
    for den in range(1, 17):
        for num in range(-32, 33):
            for c in range(0, 1025):
                if all((num * r.offset[1] + c) // den == r.offset[3] for r in creative):
                    compact_o3.append({"numerator": num, "constant": c, "denominator": den})
                    break
    compact_o3.sort(key=lambda x: (x["denominator"], abs(x["numerator"]), x["constant"]))

    return {
        "plateau_q9_ladder": {
            "hypothesis": "plateau_code + 1 == round(512 * (1.15 + 0.15*state))",
            "matches_all_7": exact,
            "rows": rows,
            "interpretation": "This exactly identifies a designed Q9-like creative-state ladder, but the +1 register-code semantics still require hardware/consumer confirmation, especially because the monochrome map stores zero rather than -1.",
        },
        "outer_border_complement": {
            "hypothesis": "CSYBD0 + CSYBD2 ~= 1023",
            "rows": outer,
            "exact_1023_count": sum(x["sum"] == 1023 for x in outer),
            "within_one_count": sum(abs(x["distance_from_1023"]) <= 1 for x in outer),
            "interpretation": "The outer thresholds are mirror-symmetric about the midpoint of a 10-bit axis to within one code. This is a strong reference-axis constraint but does not alone distinguish full-range luminance from a full-range encoded chroma metric.",
        },
        "offset3_compact_fits": {
            "top_20": compact_o3[:20],
            "interpretation": "Exact compact fits are generator clues only; the firmware may store all four offsets independently.",
        },
    }


def report(rows: list[Cat42]) -> dict:
    creative = [r for r in rows if -3 <= r.state <= 3]
    if len(creative) != 7:
        raise ValueError(f"expected 7 creative states, found {len(creative)}")
    ranked = continuity_candidates(rows)
    return {
        "schema": "m11camera.research.cat42_csp_arithmetic.v2",
        "evidence_boundary": {
            "category42_to_milbeaut_csp": "strong_structural_inference",
            "csyky_endpoint_direction": "open",
            "chroma_reference_magnitude": "open",
            "piecewise_equation": "open",
            "continuity_test_is_proof": False,
            "compact_generator_fit_is_proof": False,
        },
        "maps": [
            {
                "state": r.state,
                "map_offset_abs": hex(r.map_offset_abs),
                "map_sha256": r.map_sha256,
                "csy_enable": r.csy_enable,
                "csyky": r.csyky,
                "csytbl": r.csytbl,
                "offset": list(r.offset),
                "gain": list(r.gain),
                "border": list(r.border),
                "y_rev": r.y_rev,
                "c_rev": r.c_rev,
                "c_fixed_enable": r.c_fixed_enable,
                "cb_fixed": r.cb_fixed,
                "cr_fixed": r.cr_fixed,
                "y_offset": r.y_offset,
                "cb_offset": r.cb_offset,
                "cr_offset": r.cr_offset,
            }
            for r in rows
        ],
        "creative_state_invariants": field_invariants(rows),
        "state_sequences": {
            **{f"offset_{i}": affine_sequence([r.offset[i] for r in creative]) for i in range(4)},
            **{f"gain_{i}": affine_sequence([r.gain[i] for r in creative]) for i in range(4)},
            **{f"border_{i}": affine_sequence([r.border[i] for r in creative]) for i in range(3)},
        },
        "offset_code_over_512": {
            str(r.state): [x / 512.0 for x in r.offset] for r in creative
        },
        "creative_scale_constraints": creative_scale_constraints(creative),
        "continuity_hypothesis_search": {
            "description": "Ranks local-vs-absolute anchoring, Q0..Q12 gains, border +/-2 conventions and three signed shifts by continuity residual across all 7 creative states. Diagnostic only.",
            "top_20": ranked[:20],
            "q3_local_best": next(
                x for x in ranked
                if x["anchoring"] == "local" and x["gain_fractional_bits"] == 3
            ),
        },
    }


def to_markdown(rep: dict) -> str:
    lines = [
        "# M11-P Category-42 CSP arithmetic constraints",
        "",
        "This is a derived diagnostic report. Continuity ranking and compact algebraic fits are not proof of the hardware equation.",
        "",
        "## Category-42 controls",
        "",
        "| state | EN | KY | TBL | offsets | gains | borders | YRV | CRV | CFIX | YOF | COFB | COFR |",
        "|---:|---:|---:|---:|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rep["maps"]:
        lines.append(
            f"| {r['state']:+d} | {r['csy_enable']} | {r['csyky']} | {r['csytbl']} | "
            f"{r['offset']} | {r['gain']} | {r['border']} | {r['y_rev']} | {r['c_rev']} | "
            f"{r['c_fixed_enable']} | {r['y_offset']} | {r['cb_offset']} | {r['cr_offset']} |"
        )
    lines += ["", "## Constant fields across creative states -3..+3", ""]
    for name, info in rep["creative_state_invariants"].items():
        lines.append(f"- `{name}`: constant={info['constant']} value={info['constant_value']} values={info['values_by_state_-3_to_+3']}")

    scale = rep["creative_scale_constraints"]["plateau_q9_ladder"]
    lines += [
        "",
        "## Q9-like creative plateau ladder",
        "",
        f"Hypothesis: `{scale['hypothesis']}`; matches all seven states: **{scale['matches_all_7']}**.",
        "",
        "| state | plateau | plateau+1 | target scale | round(target*512) | match |",
        "|---:|---:|---:|---:|---:|:---:|",
    ]
    for x in scale["rows"]:
        lines.append(
            f"| {x['state']:+d} | {x['plateau_code']} | {x['plateau_plus_one']} | "
            f"{x['target_scale']:.2f} | {x['round_target_times_512']} | {x['plus_one_matches_target_q9']} |"
        )
    lines += ["", scale["interpretation"], ""]

    outer = rep["creative_scale_constraints"]["outer_border_complement"]
    lines += [
        "## Outer-border complement constraint",
        "",
        f"`CSYBD0 + CSYBD2 == 1023` in {outer['exact_1023_count']}/7 states and is within one code in {outer['within_one_count']}/7 states.",
        "",
    ]
    for x in outer["rows"]:
        lines.append(f"- state {x['state']:+d}: {x['border0']} + {x['border2']} = {x['sum']}")
    lines += ["", outer["interpretation"], ""]

    fits = rep["creative_scale_constraints"]["offset3_compact_fits"]["top_20"]
    if fits:
        f0 = fits[0]
        lines += [
            "## Compact offset[3] generator clue",
            "",
            f"A compact exact fit across all seven states is `offset3 = floor(({f0['numerator']}*plateau + {f0['constant']})/{f0['denominator']})`.",
            "This is a stored-map generator clue, not evidence that CSP hardware computes offset3 from the plateau.",
            "",
        ]

    lines += ["## Best continuity candidates", ""]
    for i, x in enumerate(rep["continuity_hypothesis_search"]["top_20"][:10], 1):
        lines.append(
            f"{i}. `{x['anchoring']}` Q{x['gain_fractional_bits']} delta={x['boundary_delta']:+d} "
            f"round={x['rounding']} -> MAE={x['mae_codes']:.4f}, RMS={x['rms_codes']:.4f}, max={x['max_abs_codes']} codes"
        )
    q3 = rep["continuity_hypothesis_search"]["q3_local_best"]
    lines += [
        "",
        "## Current Q3/local hypothesis",
        "",
        f"Best Q3/local convention in this search: delta={q3['boundary_delta']:+d}, round={q3['rounding']}, "
        f"MAE={q3['mae_codes']:.4f}, RMS={q3['rms_codes']:.4f}, max={q3['max_abs_codes']} codes.",
        "",
        "## Interpretation boundary",
        "",
        "Low continuity residual can eliminate poor hypotheses but cannot establish CSYKY endpoint direction, chroma magnitude, table selection semantics, the output coefficient encoding, or the exact multiplier/rounding datapath by itself.",
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
    args.markdown.write_text(to_markdown(rep) + "\n")
    print(args.markdown)


if __name__ == "__main__":
    main()
