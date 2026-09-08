#!/usr/bin/env python3
"""Recover a derivative slice of the M11 Standard tone gain from legacy A/B LUTs.

This is NOT a new firmware extraction.  It uses three old diagnostic cubes that
were generated from the then-recovered firmware Standard Q12 tone response:

- COLOR_LOCKED: no added Leica tone
- TONE20: 20% blend toward full recovered Standard tone
- TONE35: 35% blend toward full recovered Standard tone

If the old generator blended linearly between the colour-locked result B and the
full-tone result F,

    T_f = B + f * (F - B)

then each blend independently recovers

    F = B + (T_f - B) / f
    gain = F / B.

Agreement between the independently recovered 20% and 35% gains is the key
internal consistency check.  The candidate x coordinate follows the recorded
M11 tone-luma weights for a pure-red sample: x=(77/255)*R.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

RED_TONE_WEIGHT = 77.0 / 255.0
DEFAULT_AGREEMENT_LIMIT = 0.012
CLIP_LIMIT = 0.9995


def recover(data: dict, agreement_limit: float) -> dict:
    grid = np.asarray(data["input_grid"], np.float64)
    base = np.asarray(data["baseline_red_output"], np.float64)
    t20 = np.asarray(data["tone20_red_output"], np.float64)
    t35 = np.asarray(data["tone35_red_output"], np.float64)
    f20 = float(data["blend_fractions"]["tone20"])
    f35 = float(data["blend_fractions"]["tone35"])

    if not (len(grid) == len(base) == len(t20) == len(t35)):
        raise ValueError("legacy axis arrays have inconsistent lengths")

    rows = []
    for i in range(len(grid)):
        if base[i] <= 0:
            continue
        clipped = bool(t20[i] >= CLIP_LIMIT or t35[i] >= CLIP_LIMIT)
        full20 = base[i] + (t20[i] - base[i]) / f20
        full35 = base[i] + (t35[i] - base[i]) / f35
        g20 = full20 / base[i]
        g35 = full35 / base[i]
        disagreement = abs(g20 - g35)
        valid = bool(not clipped and disagreement <= agreement_limit)
        rows.append({
            "index": i,
            "input_grid": float(grid[i]),
            "baseline_red": float(base[i]),
            "tone20_red": float(t20[i]),
            "tone35_red": float(t35[i]),
            "full_red_from20": float(full20),
            "full_red_from35": float(full35),
            "gain_from20": float(g20),
            "gain_from35": float(g35),
            "gain_consensus": float((g20 + g35) / 2.0),
            "gain_disagreement_abs": float(disagreement),
            "x_from_baseline_red_luma": float(RED_TONE_WEIGHT * base[i]),
            "x_from_input_grid_red_luma": float(RED_TONE_WEIGHT * grid[i]),
            "clipped": clipped,
            "valid": valid,
        })

    valid_rows = [r for r in rows if r["valid"]]
    if not valid_rows:
        raise RuntimeError("no valid legacy tone samples recovered")

    diffs = np.asarray([r["gain_disagreement_abs"] for r in valid_rows])
    gains = np.asarray([r["gain_consensus"] for r in valid_rows])
    x_base = np.asarray([r["x_from_baseline_red_luma"] for r in valid_rows])
    x_grid = np.asarray([r["x_from_input_grid_red_luma"] for r in valid_rows])
    recorded_lo = data["recorded_standard_q12_gain_range"][0] / data["recorded_q12_denominator"]
    recorded_hi = data["recorded_standard_q12_gain_range"][1] / data["recorded_q12_denominator"]

    return {
        "schema": "m11camera.r2.legacy_standard_tone_slice.v1",
        "evidence_class": "recovered_from_legacy_derivative_not_firmware_reextraction",
        "source_evidence_class": data["evidence_class"],
        "recovery_equation": data["working_recovery_equation"],
        "red_tone_weight": RED_TONE_WEIGHT,
        "agreement_limit": agreement_limit,
        "clip_limit": CLIP_LIMIT,
        "recorded_standard_gain_range": [recorded_lo, recorded_hi],
        "valid_sample_count": len(valid_rows),
        "all_nonzero_sample_count": len(rows),
        "valid_gain_min": float(np.min(gains)),
        "valid_gain_max": float(np.max(gains)),
        "gain_disagreement_median": float(np.median(diffs)),
        "gain_disagreement_mean": float(np.mean(diffs)),
        "gain_disagreement_max": float(np.max(diffs)),
        "x_baseline_luma_min": float(np.min(x_base)),
        "x_baseline_luma_max": float(np.max(x_base)),
        "x_input_grid_luma_min": float(np.min(x_grid)),
        "x_input_grid_luma_max": float(np.max(x_grid)),
        "rows": rows,
    }


def write_csv(path: Path, result: dict) -> None:
    rows = result["rows"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--csv", type=Path)
    ap.add_argument("--agreement-limit", type=float, default=DEFAULT_AGREEMENT_LIMIT)
    args = ap.parse_args()

    result = recover(json.loads(args.evidence.read_text()), args.agreement_limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    if args.csv:
        write_csv(args.csv, result)

    print(f"valid samples: {result['valid_sample_count']} / {result['all_nonzero_sample_count']}")
    print(
        "blend agreement median/mean/max: "
        f"{result['gain_disagreement_median']:.6f} / "
        f"{result['gain_disagreement_mean']:.6f} / "
        f"{result['gain_disagreement_max']:.6f}"
    )
    print(
        f"recovered gain slice: {result['valid_gain_min']:.6f} .. "
        f"{result['valid_gain_max']:.6f}; recorded full Standard range "
        f"{result['recorded_standard_gain_range'][0]:.6f} .. "
        f"{result['recorded_standard_gain_range'][1]:.6f}"
    )
    print(
        f"candidate x (baseline-red luma): {result['x_baseline_luma_min']:.6f} .. "
        f"{result['x_baseline_luma_max']:.6f}"
    )


if __name__ == "__main__":
    main()
