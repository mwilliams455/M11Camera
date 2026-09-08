#!/usr/bin/env python3
"""Probe genuine Leica M11 DNG metadata against recovered firmware colour stages.

This script tests two distinct hypotheses:

H0 (now expected to fail away from tungsten):
    as-shot white-balanced M11 camera RGB -> fixed CC0 -> fixed low-ISO CC1

H1 (firmware-consistent reference-basis model):
    as-shot white-balanced M11 camera RGB
      -> scene-dependent DNG/firmware colour-management bridge
      -> fixed Standard-A reference camera basis
      -> fixed CC0 -> tone -> fixed low-ISO CC1

The H1 pre-CC0 bridge is derived only from the genuine M11 ColorMatrix family and
white point. It is independent of the assumed output RGB gamut because the common
PCS/output transform cancels in the basis-change matrix.

Evidence note: CC0/CC1 values remain recorded prior findings until independently
re-extracted from firmware. Category 13 is known from prior research to vary at
very high ISO; the Photography Blog corpus here is entirely in the low-ISO band.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import numpy as np

CC0_Q9 = np.array(
    [[495, -58, 63], [10, 601, -111], [49, -255, 705]], dtype=np.float64
)
CC1_Q9 = np.array(
    [[1041, -372, -157], [-117, 630, -1], [-4, -78, 595]], dtype=np.float64
)
CC0 = CC0_Q9 / 512.0
CC1 = CC1_Q9 / 512.0
CC_COMBINED = CC1 @ CC0

# DNG PCS is XYZ D50. Convert PCS to linear sRGB/BT.709 only for the diagnostic
# comparison of the combined colour matrix; the pre-CC0 basis bridge itself does
# not depend on this output transform.
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
D50_XY = (0.34567, 0.35850)
D65_XY = (0.31271, 0.32902)
STANDARD_A_XY = (0.44757, 0.40745)

ILLUMINANT_K = {
    1: 6504, 2: 4230, 3: 2856, 4: 5500, 9: 5500, 10: 6500, 11: 7500,
    12: 6430, 13: 5000, 14: 4230, 15: 3450, 17: 2856, 18: 4874,
    19: 6774, 20: 5503, 21: 6504, 22: 7504, 23: 5003, 24: 3200,
}


def suffix_lookup(obj: dict[str, Any], suffix: str) -> Any | None:
    suffix = suffix.lower()
    vals = [v for k, v in obj.items() if k.split(":")[-1].lower() == suffix]
    for value in vals:
        if value not in (None, "", []):
            return value
    return vals[0] if vals else None


def parse_numbers(value: Any, expected: int | None = None) -> np.ndarray:
    if isinstance(value, (int, float)):
        nums = [float(value)]
    elif isinstance(value, list):
        nums = [float(v) for v in value]
    elif isinstance(value, str):
        cleaned = value.replace(",", " ").replace("[", " ").replace("]", " ")
        nums = []
        for token in cleaned.split():
            if "/" in token:
                a, b = token.split("/", 1)
                nums.append(float(a) / float(b))
            else:
                nums.append(float(token))
    else:
        raise ValueError(f"cannot parse numeric vector from {value!r}")
    arr = np.asarray(nums, dtype=np.float64)
    if expected is not None and arr.size != expected:
        raise ValueError(f"expected {expected} values, got {arr.size}: {value!r}")
    return arr


def parse_scalar(value: Any) -> float | None:
    if value is None:
        return None
    arr = parse_numbers(value)
    return float(arr[0]) if arr.size else None


def xy_to_xyz(xy: tuple[float, float]) -> np.ndarray:
    x, y = xy
    return np.array([x / y, 1.0, (1.0 - x - y) / y], dtype=np.float64)


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
    illuminant1: int, illuminant2: int, cm1: np.ndarray, cm2: np.ndarray,
    neutral: np.ndarray,
) -> float:
    """Photon-style iterative reciprocal-CCT factor; factor=0 CM1, factor=1 CM2."""
    t1, t2 = float(ILLUMINANT_K[illuminant1]), float(ILLUMINANT_K[illuminant2])
    lower, upper = min(t1, t2), max(t1, t2)
    factor = old = 0.5
    for _ in range(30):
        cm = lerp(cm1, cm2, factor)
        xyz_white = np.linalg.inv(cm) @ neutral
        temp = mccamy_cct(*cie_xy(xyz_white))
        if temp <= lower:
            new = 1.0
        elif temp >= upper:
            new = 0.0
        else:
            new = (1.0 / temp - 1.0 / upper) / (1.0 / lower - 1.0 / upper)
        if lower == t1:
            new = 1.0 - new
        factor = 0.5 * (new + old)
        if abs(old - factor) <= 1e-4:
            break
        old = factor
    return float(factor)


def bradford(white1_xy: tuple[float, float], white2_xy: tuple[float, float]) -> np.ndarray:
    """Adobe DNG SDK MapWhiteMatrix direction: white1 -> white2."""
    w1 = BRADFORD @ xy_to_xyz(white1_xy)
    w2 = BRADFORD @ xy_to_xyz(white2_xy)
    ratios = np.clip(np.where(w1 > 0.0, w2 / w1, 10.0), 0.1, 10.0)
    return BRADFORD_INV @ np.diag(ratios) @ BRADFORD


def dng_no_forward_wb_camera_to_pcs(
    cm: np.ndarray, white_xy: tuple[float, float]
) -> tuple[np.ndarray, np.ndarray, float]:
    """Reconstruct Adobe DNG SDK's no-ForwardMatrix SetWhiteXY path.

    Returns a transform from *white-balanced camera coordinates* to XYZ D50 PCS,
    the normalized camera white, and the SDK reach-saturation scale.
    """
    camera_white = cm @ xy_to_xyz(white_xy)
    camera_white = camera_white / np.max(camera_white)
    camera_white = np.clip(camera_white, 0.001, 1.0)

    pcs_to_camera = cm @ bradford(D50_XY, white_xy)
    reach_scale = float(np.max(pcs_to_camera @ xy_to_xyz(D50_XY)))
    pcs_to_camera = pcs_to_camera / reach_scale
    camera_to_pcs = np.linalg.inv(pcs_to_camera)
    wb_camera_to_pcs = camera_to_pcs @ np.diag(camera_white)
    return wb_camera_to_pcs, camera_white, reach_scale


def pcs_to_linear_srgb() -> np.ndarray:
    return XYZ_D65_TO_SRGB @ bradford(D50_XY, D65_XY)


def optimal_common_scale(reference: np.ndarray, candidate: np.ndarray) -> float:
    denom = float(np.sum(candidate * candidate))
    if denom <= 0:
        raise ValueError("candidate matrix has zero norm")
    return float(np.sum(reference * candidate) / denom)


def matrix_metrics(reference: np.ndarray, candidate: np.ndarray) -> dict[str, float]:
    scale = optimal_common_scale(reference, candidate)
    return {
        "candidate_common_scale_to_reference": scale,
        "relative_frobenius_error_raw": float(
            np.linalg.norm(reference - candidate) / np.linalg.norm(reference)
        ),
        "relative_frobenius_error_after_common_scale": float(
            np.linalg.norm(reference - scale * candidate) / np.linalg.norm(reference)
        ),
    }


def filename_stem(record: dict[str, Any]) -> str:
    return Path(str(record.get("SourceFile", ""))).stem


def analyze_dng(record: dict[str, Any]) -> dict[str, Any]:
    neutral = parse_numbers(suffix_lookup(record, "AsShotNeutral"), 3)
    cm1 = parse_numbers(suffix_lookup(record, "ColorMatrix1"), 9).reshape(3, 3)
    cm2 = parse_numbers(suffix_lookup(record, "ColorMatrix2"), 9).reshape(3, 3)
    ill1 = int(parse_scalar(suffix_lookup(record, "CalibrationIlluminant1")))
    ill2 = int(parse_scalar(suffix_lookup(record, "CalibrationIlluminant2")))

    factor = solve_interpolation_factor(ill1, ill2, cm1, cm2, neutral)
    cm = lerp(cm1, cm2, factor)
    scene_xyz_white = np.linalg.inv(cm) @ neutral
    scene_white_xy = cie_xy(scene_xyz_white)
    scene_cct = mccamy_cct(*scene_white_xy)

    scene_wb_to_pcs, scene_cam_white, scene_reach_scale = dng_no_forward_wb_camera_to_pcs(
        cm, scene_white_xy
    )
    # CM1 is tagged Standard Light A in genuine M11 DNGs. This is the fixed
    # reference basis suggested by the firmware evidence and by the CC product fit.
    a_wb_to_pcs, a_cam_white, a_reach_scale = dng_no_forward_wb_camera_to_pcs(
        cm1, STANDARD_A_XY
    )
    pcs_to_a_reference_wb_camera = np.linalg.inv(a_wb_to_pcs)
    scene_to_a_reference = pcs_to_a_reference_wb_camera @ scene_wb_to_pcs

    out = pcs_to_linear_srgb()
    scene_wb_to_srgb = out @ scene_wb_to_pcs
    a_wb_to_srgb = out @ a_wb_to_pcs

    direct = matrix_metrics(scene_wb_to_srgb, CC_COMBINED)
    bridged_candidate = CC_COMBINED @ scene_to_a_reference
    bridged = matrix_metrics(scene_wb_to_srgb, bridged_candidate)
    a_reference_fit = matrix_metrics(a_wb_to_srgb, CC_COMBINED)

    def optional(name: str) -> Any:
        value = suffix_lookup(record, name)
        return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)

    return {
        "stem": filename_stem(record),
        "iso": parse_scalar(suffix_lookup(record, "ISO")),
        "exposure_time": optional("ExposureTime"),
        "model": optional("Model"),
        "software": optional("Software"),
        "black_level": optional("BlackLevel"),
        "white_level": optional("WhiteLevel"),
        "calibration_illuminant1": ill1,
        "calibration_illuminant2": ill2,
        "as_shot_neutral": neutral.tolist(),
        "interpolation_factor_cm1_to_cm2": factor,
        "estimated_scene_white_xy": list(scene_white_xy),
        "estimated_scene_cct_mccamy_k": scene_cct,
        "interpolated_color_matrix": cm.tolist(),
        "scene_camera_white_sdk_normalized": scene_cam_white.tolist(),
        "scene_wb_camera_to_xyz_d50_pcs": scene_wb_to_pcs.tolist(),
        "standard_a_reference_camera_white": a_cam_white.tolist(),
        "standard_a_wb_camera_to_xyz_d50_pcs": a_wb_to_pcs.tolist(),
        "xyz_d50_pcs_to_standard_a_reference_wb_camera": pcs_to_a_reference_wb_camera.tolist(),
        "scene_wb_camera_to_standard_a_reference_wb_camera": scene_to_a_reference.tolist(),
        "scene_wb_camera_to_linear_srgb": scene_wb_to_srgb.tolist(),
        "standard_a_reference_wb_camera_to_linear_srgb": a_wb_to_srgb.tolist(),
        "recorded_firmware_cc1_times_cc0": CC_COMBINED.tolist(),
        "sdk_reach_saturation_scale_scene": scene_reach_scale,
        "sdk_reach_saturation_scale_standard_a": a_reach_scale,
        "comparisons": {
            "H0_direct_scene_wb_camera_to_fixed_cc_product": direct,
            "H1_scene_to_A_reference_then_fixed_cc_product": bridged,
            "fixed_cc_product_vs_standard_A_reference_output": a_reference_fit,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exif", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    records = json.loads(args.exif.read_text())
    dngs = [r for r in records if str(r.get("SourceFile", "")).lower().endswith(".dng")]
    results = sorted((analyze_dng(r) for r in dngs), key=lambda x: x["stem"])

    h0 = [r["comparisons"]["H0_direct_scene_wb_camera_to_fixed_cc_product"]["relative_frobenius_error_after_common_scale"] for r in results]
    h1 = [r["comparisons"]["H1_scene_to_A_reference_then_fixed_cc_product"]["relative_frobenius_error_after_common_scale"] for r in results]
    aref = [r["comparisons"]["fixed_cc_product_vs_standard_A_reference_output"]["relative_frobenius_error_after_common_scale"] for r in results]
    scales = [r["comparisons"]["H1_scene_to_A_reference_then_fixed_cc_product"]["candidate_common_scale_to_reference"] for r in results]

    summary = {
        "schema": "m11camera.r1.matched_dng_reference_basis_probe.v2",
        "evidence_note": "CC0/CC1 are recorded prior findings pending reproducible firmware re-extraction.",
        "hypotheses": {
            "H0": "scene white-balanced M11 camera RGB directly enters fixed CC0/CC1",
            "H1": "scene white-balanced M11 camera RGB is first mapped through interpolated colour management into the Standard-A reference camera basis, then enters fixed CC0/tone/CC1",
        },
        "cc0_q9": CC0_Q9.astype(int).tolist(),
        "cc1_low_iso_q9": CC1_Q9.astype(int).tolist(),
        "cc1_times_cc0": CC_COMBINED.tolist(),
        "sample_count": len(results),
        "aggregate": {
            "H0_mean_scaled_error": float(np.mean(h0)) if h0 else None,
            "H0_max_scaled_error": float(np.max(h0)) if h0 else None,
            "H1_mean_scaled_error": float(np.mean(h1)) if h1 else None,
            "H1_max_scaled_error": float(np.max(h1)) if h1 else None,
            "standard_A_reference_mean_scaled_error": float(np.mean(aref)) if aref else None,
            "H1_mean_common_scale": float(np.mean(scales)) if scales else None,
        },
        "samples": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n")

    print(json.dumps(summary["aggregate"], indent=2))
    for s in results:
        h0e = s["comparisons"]["H0_direct_scene_wb_camera_to_fixed_cc_product"]["relative_frobenius_error_after_common_scale"]
        h1e = s["comparisons"]["H1_scene_to_A_reference_then_fixed_cc_product"]["relative_frobenius_error_after_common_scale"]
        print(
            f"{s['stem']}: ISO={s['iso']:.0f} CCT~{s['estimated_scene_cct_mccamy_k']:.0f}K "
            f"H0={100*h0e:.3f}% H1={100*h1e:.3f}%"
        )


if __name__ == "__main__":
    main()
