#!/usr/bin/env python3
"""Probe genuine Leica M11 DNG metadata against the recovered CC0/CC1 model.

This script consumes ExifTool JSON generated from original M11 DNG/JPEG pairs.
It does not depend on image pixels. Its purpose is to test whether the recovered
firmware matrices are consistent with an already-white-balanced M11 camera-RGB
signal whose combined CC1*CC0 transform lands close to linear sRGB/BT.709.

Evidence note: CC0/CC1 values are recorded prior findings until independently
re-extracted from firmware. Results from this script are therefore hypothesis
validation, not firmware proof.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import numpy as np

CC0_Q9 = np.array(
    [
        [495, -58, 63],
        [10, 601, -111],
        [49, -255, 705],
    ],
    dtype=np.float64,
)
CC1_Q9 = np.array(
    [
        [1041, -372, -157],
        [-117, 630, -1],
        [-4, -78, 595],
    ],
    dtype=np.float64,
)
CC0 = CC0_Q9 / 512.0
CC1 = CC1_Q9 / 512.0
CC_COMBINED = CC1 @ CC0

# Linear XYZ(D65) -> sRGB / BT.709 primaries.
XYZ_D65_TO_SRGB = np.array(
    [
        [3.2404542, -1.5371385, -0.4985314],
        [-0.9692660, 1.8760108, 0.0415560],
        [0.0556434, -0.2040259, 1.0572252],
    ],
    dtype=np.float64,
)

BRADFORD = np.array(
    [
        [0.8951, 0.2664, -0.1614],
        [-0.7502, 1.7135, 0.0367],
        [0.0389, -0.0685, 1.0296],
    ],
    dtype=np.float64,
)
BRADFORD_INV = np.linalg.inv(BRADFORD)
D65_XYZ = np.array([0.95047, 1.0, 1.08883], dtype=np.float64)

ILLUMINANT_K = {
    1: 6504,
    2: 4230,
    3: 2856,
    4: 5500,
    9: 5500,
    10: 6500,
    11: 7500,
    12: 6430,
    13: 5000,
    14: 4230,
    15: 3450,
    17: 2856,
    18: 4874,
    19: 6774,
    20: 5503,
    21: 6504,
    22: 7504,
    23: 5003,
    24: 3200,
}


def suffix_lookup(obj: dict[str, Any], suffix: str) -> Any | None:
    suffix = suffix.lower()
    exact = []
    for key, value in obj.items():
        tail = key.split(":")[-1].lower()
        if tail == suffix:
            exact.append(value)
    if not exact:
        return None
    # Prefer the first non-empty value. ExifTool -a may emit duplicate group keys,
    # but group-qualified JSON keys are generally unique.
    for value in exact:
        if value not in (None, "", []):
            return value
    return exact[0]


def parse_numbers(value: Any, expected: int | None = None) -> np.ndarray:
    if isinstance(value, (int, float)):
        numbers = [float(value)]
    elif isinstance(value, list):
        numbers = [float(v) for v in value]
    elif isinstance(value, str):
        cleaned = value.replace(",", " ").replace("[", " ").replace("]", " ")
        numbers = []
        for token in cleaned.split():
            if "/" in token:
                a, b = token.split("/", 1)
                numbers.append(float(a) / float(b))
            else:
                numbers.append(float(token))
    else:
        raise ValueError(f"cannot parse numeric vector from {value!r}")
    arr = np.asarray(numbers, dtype=np.float64)
    if expected is not None and arr.size != expected:
        raise ValueError(f"expected {expected} values, got {arr.size}: {value!r}")
    return arr


def parse_scalar(value: Any) -> float | None:
    if value is None:
        return None
    arr = parse_numbers(value)
    return float(arr[0]) if arr.size else None


def cie_xy(xyz: np.ndarray) -> tuple[float, float]:
    s = float(np.sum(xyz))
    if not math.isfinite(s) or abs(s) < 1e-12:
        raise ValueError("invalid XYZ white")
    return float(xyz[0] / s), float(xyz[1] / s)


def mccamy_cct(x: float, y: float) -> float:
    denom = y - 0.1858
    if abs(denom) < 1e-9:
        denom = -1e-9 if denom < 0 else 1e-9
    n = (x - 0.332) / denom
    return float(-449.0 * n**3 + 3525.0 * n**2 - 6823.3 * n + 5520.33)


def lerp(a: np.ndarray, b: np.ndarray, factor: float) -> np.ndarray:
    return a * (1.0 - factor) + b * factor


def solve_interpolation_factor(
    illuminant1: int,
    illuminant2: int,
    cm1: np.ndarray,
    cm2: np.ndarray,
    neutral: np.ndarray,
) -> float:
    t1 = float(ILLUMINANT_K[illuminant1])
    t2 = float(ILLUMINANT_K[illuminant2])
    lower, upper = min(t1, t2), max(t1, t2)
    factor = old_factor = 0.5
    for _ in range(30):
        cm = lerp(cm1, cm2, factor)
        xyz_white = np.linalg.inv(cm) @ neutral
        x, y = cie_xy(xyz_white)
        temp = mccamy_cct(x, y)
        if temp <= lower:
            new_factor = 1.0
        elif temp >= upper:
            new_factor = 0.0
        else:
            inv_t = 1.0 / temp
            new_factor = (inv_t - 1.0 / upper) / (1.0 / lower - 1.0 / upper)
        if lower == t1:
            new_factor = 1.0 - new_factor
        factor = 0.5 * (new_factor + old_factor)
        diff = abs(old_factor - factor)
        old_factor = factor
        if diff <= 1e-4:
            break
    return float(factor)


def bradford_adaptation(src_white_xyz: np.ndarray, dst_white_xyz: np.ndarray) -> np.ndarray:
    src_lms = BRADFORD @ src_white_xyz
    dst_lms = BRADFORD @ dst_white_xyz
    if np.any(np.abs(src_lms) < 1e-12):
        raise ValueError("singular Bradford source white")
    return BRADFORD_INV @ np.diag(dst_lms / src_lms) @ BRADFORD


def wb_camera_to_linear_srgb(
    cm: np.ndarray,
    neutral: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, float]:
    """Return white-balanced M11 camera RGB -> linear sRGB matrix.

    Let raw camera RGB be c. DNG AsShotNeutral n represents the camera response
    to the scene neutral. White-balanced camera RGB is c_wb = diag(1/n) c (up
    to a common exposure scalar), therefore c = diag(n) c_wb.

    The interpolated ColorMatrix is XYZ(scene-white) -> camera. We invert it,
    adapt the recovered scene white to D65 with Bradford, then convert XYZ D65
    to linear sRGB.
    """
    xyz_white = np.linalg.inv(cm) @ neutral
    # Normalize the source white to Y=1 before chromatic adaptation.
    if abs(xyz_white[1]) < 1e-12:
        raise ValueError("scene white has zero Y")
    src_white = xyz_white / xyz_white[1]
    cat = bradford_adaptation(src_white, D65_XYZ)
    matrix = XYZ_D65_TO_SRGB @ cat @ np.linalg.inv(cm) @ np.diag(neutral)
    return matrix, src_white, mccamy_cct(*cie_xy(src_white))


def optimal_common_scale(reference: np.ndarray, candidate: np.ndarray) -> float:
    denom = float(np.sum(candidate * candidate))
    if denom <= 0:
        raise ValueError("candidate matrix has zero norm")
    return float(np.sum(reference * candidate) / denom)


def matrix_metrics(reference: np.ndarray, candidate: np.ndarray) -> dict[str, float]:
    raw_diff = reference - candidate
    raw_rel = float(np.linalg.norm(raw_diff) / np.linalg.norm(reference))
    scale = optimal_common_scale(reference, candidate)
    scaled = candidate * scale
    scaled_rel = float(np.linalg.norm(reference - scaled) / np.linalg.norm(reference))
    return {
        "candidate_common_scale_to_reference": scale,
        "relative_frobenius_error_raw": raw_rel,
        "relative_frobenius_error_after_common_scale": scaled_rel,
    }


def filename_stem(record: dict[str, Any]) -> str:
    source = str(record.get("SourceFile", ""))
    return Path(source).stem


def analyze_dng(record: dict[str, Any]) -> dict[str, Any]:
    stem = filename_stem(record)
    neutral = parse_numbers(suffix_lookup(record, "AsShotNeutral"), 3)
    cm1 = parse_numbers(suffix_lookup(record, "ColorMatrix1"), 9).reshape(3, 3)
    cm2 = parse_numbers(suffix_lookup(record, "ColorMatrix2"), 9).reshape(3, 3)
    ill1 = int(parse_scalar(suffix_lookup(record, "CalibrationIlluminant1")))
    ill2 = int(parse_scalar(suffix_lookup(record, "CalibrationIlluminant2")))
    factor = solve_interpolation_factor(ill1, ill2, cm1, cm2, neutral)
    cm = lerp(cm1, cm2, factor)
    wb_to_srgb, src_white, cct = wb_camera_to_linear_srgb(cm, neutral)
    metrics = matrix_metrics(wb_to_srgb, CC_COMBINED)

    def optional(name: str) -> Any:
        value = suffix_lookup(record, name)
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    return {
        "stem": stem,
        "iso": parse_scalar(suffix_lookup(record, "ISO")),
        "exposure_time": optional("ExposureTime"),
        "f_number": parse_scalar(suffix_lookup(record, "FNumber")),
        "model": optional("Model"),
        "software": optional("Software"),
        "black_level": optional("BlackLevel"),
        "white_level": optional("WhiteLevel"),
        "calibration_illuminant1": ill1,
        "calibration_illuminant2": ill2,
        "as_shot_neutral": neutral.tolist(),
        "color_matrix1": cm1.tolist(),
        "color_matrix2": cm2.tolist(),
        "interpolation_factor_cm1_to_cm2": factor,
        "estimated_scene_white_xyz_y1": src_white.tolist(),
        "estimated_scene_cct_mccamy_k": cct,
        "interpolated_color_matrix": cm.tolist(),
        "derived_wb_camera_to_linear_srgb": wb_to_srgb.tolist(),
        "recorded_firmware_cc1_times_cc0": CC_COMBINED.tolist(),
        "comparison": metrics,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exif", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    records = json.loads(args.exif.read_text())
    dngs = [r for r in records if str(r.get("SourceFile", "")).lower().endswith(".dng")]
    results = [analyze_dng(r) for r in dngs]
    results.sort(key=lambda x: x["stem"])

    scaled_errors = [r["comparison"]["relative_frobenius_error_after_common_scale"] for r in results]
    scales = [r["comparison"]["candidate_common_scale_to_reference"] for r in results]
    summary = {
        "schema": "m11camera.r1.matched_dng_metadata_probe.v1",
        "evidence_note": "CC0/CC1 are recorded prior findings pending reproducible firmware re-extraction.",
        "hypothesis": "M11 as-shot white-balanced camera RGB -> CC0 -> tone -> CC1, with CC1*CC0 approximating white-balanced M11 sensor -> linear sRGB/BT.709 up to common gain when tone is neutralized.",
        "cc0_q9": CC0_Q9.astype(int).tolist(),
        "cc1_q9": CC1_Q9.astype(int).tolist(),
        "cc1_times_cc0": CC_COMBINED.tolist(),
        "sample_count": len(results),
        "aggregate": {
            "mean_relative_error_after_common_scale": float(np.mean(scaled_errors)) if scaled_errors else None,
            "max_relative_error_after_common_scale": float(np.max(scaled_errors)) if scaled_errors else None,
            "min_relative_error_after_common_scale": float(np.min(scaled_errors)) if scaled_errors else None,
            "mean_candidate_common_scale_to_reference": float(np.mean(scales)) if scales else None,
        },
        "samples": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n")

    print(json.dumps(summary["aggregate"], indent=2))
    for sample in results:
        c = sample["comparison"]
        print(
            f"{sample['stem']}: ISO={sample['iso']} CCT~{sample['estimated_scene_cct_mccamy_k']:.0f}K "
            f"factor={sample['interpolation_factor_cm1_to_cm2']:.6f} "
            f"scaled_err={100*c['relative_frobenius_error_after_common_scale']:.3f}% "
            f"scale={c['candidate_common_scale_to_reference']:.6f}"
        )


if __name__ == "__main__":
    main()
