#!/usr/bin/env python3
"""Test M11 tone placement and JPEG output domain without fitting a tone curve.

Under the current firmware-derived Standard model:

    reference RGB -> CC0 -> scalar tone gain g(Ytone) -> CC1
                  -> YCC -> Y-only gamma -> 1.15 * (Cb,Cr) -> inverse YCC
                  -> final output transfer

A scalar commutes with the linear CC1 matrix, and Y-only gamma does not alter
Cb/Cr.  Therefore, before a nonlinear final RGB transfer:

    |C_out| / (1.15 * |C_pre|) = g(Ytone)

where C_pre is chroma after CC1*CC0 but before tone, and Ytone is the recovered
tone-control luma after CC0.

This probe asks which observed JPEG domain makes that ratio most nearly a single
shared function of Ytone across 12 genuine matched M11 RAW/JPEG pairs:

- JPEG code values directly
- JPEG decoded with the standard sRGB OETF

It also compares the H0 direct-WB-camera basis with the H1 Standard-A reference
basis.  No per-scene matrix, tone curve or local correction is fitted.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import cv2
import numpy as np

# When run as `python tools/probe_...py`, the tools directory is sys.path[0].
import probe_m11_pixel_chroma_fast as base

TONE_Y = np.array([77, 149, 29], np.float32) / 255.0
STANDARD_CHROMA = 1.15
RECORDED_STANDARD_GAIN_RANGE = (1911 / 4096.0, 4867 / 4096.0)
BIN_EDGES = np.linspace(0.02, 0.92, 31)
MAX_POINTS_PER_PAIR_ROUTE = 180_000


def srgb_encode(x: np.ndarray) -> np.ndarray:
    x = np.maximum(np.asarray(x, np.float32), 0.0)
    return np.where(
        x <= 0.0031308,
        12.92 * x,
        1.055 * np.power(x, 1.0 / 2.4) - 0.055,
    ).astype(np.float32)


def basis_matrices(meta: dict) -> tuple[dict[str, np.ndarray], dict]:
    cm, white_xy, factor, cct = base.solve_scene(meta)
    scene_cam_to_pcs = base.camera_to_pcs(cm, white_xy)
    scene_white = base.camera_white(cm, white_xy)
    a_wb_to_pcs = base.wb_camera_to_pcs(meta["cm1"], base.A_XY)
    pcs_to_a = np.linalg.inv(a_wb_to_pcs)
    return {
        "H0": np.diag(1.0 / scene_white),
        "H1": pcs_to_a @ scene_cam_to_pcs,
    }, {
        "factor": factor,
        "cct": cct,
        "white_xy": list(white_xy),
        "scene_camera_white": scene_white.tolist(),
    }


def warp_scalar(values: np.ndarray, target_shape, warp: np.ndarray) -> np.ndarray:
    h, w = target_shape[:2]
    resized = cv2.resize(values.astype(np.float32), (w, h), interpolation=cv2.INTER_AREA)
    return cv2.warpAffine(
        resized,
        warp,
        (w, h),
        flags=cv2.INTER_LINEAR | cv2.WARP_INVERSE_MAP,
        borderMode=cv2.BORDER_CONSTANT,
        borderValue=np.nan,
    )


def gradient_magnitude(luma: np.ndarray) -> np.ndarray:
    x = np.nan_to_num(luma.astype(np.float32), nan=0.0)
    gx = cv2.Sobel(x, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(x, cv2.CV_32F, 0, 1, ksize=3)
    return np.hypot(gx, gy)


def deterministic_subsample(arrays: list[np.ndarray], max_points: int) -> list[np.ndarray]:
    n = arrays[0].size
    if n <= max_points:
        return arrays
    # Deterministic evenly spaced sample avoids random-run drift and does not use
    # image content to cherry-pick points.
    idx = np.linspace(0, n - 1, max_points, dtype=np.int64)
    return [a[idx] for a in arrays]


def extract_route_points(
    raw: np.ndarray,
    jpg_linear: np.ndarray,
    basis: np.ndarray,
    warp: np.ndarray,
) -> dict[str, np.ndarray]:
    ref = base.apply(raw, basis)
    cc0 = base.apply(ref, base.CC0)
    pre = base.apply(cc0, base.CC1)

    tone_y = np.einsum("...j,j->...", cc0, TONE_Y, optimize=True).astype(np.float32)
    pre_ycc = base.apply(pre, base.YCC)
    pre_c = np.hypot(pre_ycc[..., 1], pre_ycc[..., 2]).astype(np.float32)

    h, w = jpg_linear.shape[:2]
    tone_y = warp_scalar(tone_y, jpg_linear.shape, warp)
    pre_c = warp_scalar(pre_c, jpg_linear.shape, warp)
    pre_min = warp_scalar(np.min(pre, axis=-1), jpg_linear.shape, warp)
    pre_max = warp_scalar(np.max(pre, axis=-1), jpg_linear.shape, warp)

    jpg_code = srgb_encode(jpg_linear)
    ycc_linear = base.apply(jpg_linear, base.YCC)
    ycc_code = base.apply(jpg_code, base.YCC)
    c_linear = np.hypot(ycc_linear[..., 1], ycc_linear[..., 2]).astype(np.float32)
    c_code = np.hypot(ycc_code[..., 1], ycc_code[..., 2]).astype(np.float32)

    # Alignment errors dominate at strong edges.  Use a content-independent
    # percentile rule on output luma gradient, shared by both domain hypotheses.
    grad = gradient_magnitude(ycc_linear[..., 0])
    grad_cut = float(np.percentile(grad[np.isfinite(grad)], 70))

    valid = (
        np.isfinite(tone_y)
        & np.isfinite(pre_c)
        & (tone_y >= BIN_EDGES[0])
        & (tone_y <= BIN_EDGES[-1])
        & (pre_c > 0.008)
        & (pre_min > -0.02)
        & (pre_max < 1.05)
        & np.all(jpg_linear > 0.002, axis=-1)
        & np.all(jpg_linear < 0.97, axis=-1)
        & (c_linear > 0.006)
        & (c_code > 0.006)
        & (grad <= grad_cut)
    )

    margin = max(6, round(min(h, w) * 0.025))
    valid[:margin] = False
    valid[-margin:] = False
    valid[:, :margin] = False
    valid[:, -margin:] = False

    tone = tone_y[valid].astype(np.float64)
    cpre = pre_c[valid].astype(np.float64)
    glin = c_linear[valid].astype(np.float64) / (STANDARD_CHROMA * cpre)
    gcode = c_code[valid].astype(np.float64) / (STANDARD_CHROMA * cpre)

    finite = (
        np.isfinite(tone) & np.isfinite(glin) & np.isfinite(gcode)
        & (glin > 0) & (gcode > 0)
        & (glin < 8) & (gcode < 8)
    )
    tone, glin, gcode = tone[finite], glin[finite], gcode[finite]
    tone, glin, gcode = deterministic_subsample(
        [tone, glin, gcode], MAX_POINTS_PER_PAIR_ROUTE
    )
    return {
        "tone_y": tone,
        "linear": glin,
        "code": gcode,
        "raw_valid_count_before_subsample": int(np.count_nonzero(finite)),
        "gradient_cut": grad_cut,
    }


def binned_scene_medians(tone: np.ndarray, gain: np.ndarray) -> list[dict]:
    bins = np.digitize(tone, BIN_EDGES) - 1
    rows = []
    for i in range(len(BIN_EDGES) - 1):
        x = gain[bins == i]
        if x.size < 100:
            continue
        rows.append({
            "bin": i,
            "x_lo": float(BIN_EDGES[i]),
            "x_hi": float(BIN_EDGES[i + 1]),
            "x_mid": float((BIN_EDGES[i] + BIN_EDGES[i + 1]) / 2),
            "n": int(x.size),
            "median": float(np.median(x)),
            "p25": float(np.percentile(x, 25)),
            "p75": float(np.percentile(x, 75)),
        })
    return rows


def summarize_consistency(pair_records: list[dict], route: str, domain: str) -> dict:
    by_bin: dict[int, list[tuple[str, float, int]]] = {}
    pooled_gain = []
    for p in pair_records:
        rows = p["routes"][route][domain]["bins"]
        for r in rows:
            by_bin.setdefault(r["bin"], []).append((p["stem"], r["median"], r["n"]))
        pooled_gain.extend(p["routes"][route][domain]["gain_values_for_summary"])

    bin_results = []
    log_residuals = []
    for i, entries in sorted(by_bin.items()):
        if len(entries) < 3:
            continue
        vals = np.array([e[1] for e in entries], np.float64)
        center = float(np.median(vals))
        if center <= 0:
            continue
        lr = np.abs(np.log(vals / center))
        log_residuals.extend(lr.tolist())
        bin_results.append({
            "bin": i,
            "x_lo": float(BIN_EDGES[i]),
            "x_hi": float(BIN_EDGES[i + 1]),
            "scene_count": len(entries),
            "median_gain": center,
            "scene_median_p25": float(np.percentile(vals, 25)),
            "scene_median_p75": float(np.percentile(vals, 75)),
            "scene_log_mad": float(np.median(lr)),
        })

    pooled = np.asarray(pooled_gain, np.float64)
    lo_rec, hi_rec = RECORDED_STANDARD_GAIN_RANGE
    return {
        "eligible_bin_count": len(bin_results),
        "scene_bin_log_abs_residual_median": float(np.median(log_residuals)) if log_residuals else None,
        "scene_bin_log_abs_residual_mean": float(np.mean(log_residuals)) if log_residuals else None,
        "pooled_gain_p05": float(np.percentile(pooled, 5)) if pooled.size else None,
        "pooled_gain_p50": float(np.percentile(pooled, 50)) if pooled.size else None,
        "pooled_gain_p95": float(np.percentile(pooled, 95)) if pooled.size else None,
        "recorded_standard_gain_min": lo_rec,
        "recorded_standard_gain_max": hi_rec,
        "bins": bin_results,
    }


def analyze_pair(dng: Path, jpg: Path) -> dict:
    meta = base.metadata(dng)
    bases, bridge = basis_matrices(meta)
    raw, rawdiag = base.read_camera_rgb(dng)
    jpg_linear, jpgdiag = base.read_jpeg(jpg)

    # Geometry is estimated once from H1's pre-tone colour output, exactly as in
    # the preceding chroma-angle experiment, then shared by all hypotheses.
    h1_pre = base.apply(base.apply(raw, bases["H1"]), base.CC)
    _, warp, ecc, valid = base.align(jpg_linear, h1_pre)
    if not valid:
        return {
            "stem": dng.stem,
            "iso": meta["iso"],
            "alignment": {"ecc": ecc, "valid": False},
            "routes": {},
        }

    routes = {}
    for route, basis in bases.items():
        pts = extract_route_points(raw, jpg_linear, basis, warp)
        route_obj = {
            "raw_valid_count_before_subsample": pts["raw_valid_count_before_subsample"],
            "sample_count": int(pts["tone_y"].size),
            "gradient_cut": pts["gradient_cut"],
        }
        for domain in ("linear", "code"):
            gains = pts[domain]
            # Keep only a small deterministic summary sample in the in-memory
            # aggregate; raw per-pixel arrays are never written to artifacts.
            if gains.size > 5000:
                ix = np.linspace(0, gains.size - 1, 5000, dtype=np.int64)
                summary_vals = gains[ix]
            else:
                summary_vals = gains
            route_obj[domain] = {
                "bins": binned_scene_medians(pts["tone_y"], gains),
                "gain_p05": float(np.percentile(gains, 5)) if gains.size else None,
                "gain_p50": float(np.percentile(gains, 50)) if gains.size else None,
                "gain_p95": float(np.percentile(gains, 95)) if gains.size else None,
                "gain_values_for_summary": summary_vals.tolist(),
            }
        routes[route] = route_obj

    return {
        "stem": dng.stem,
        "iso": meta["iso"],
        "bridge": bridge,
        "alignment": {"ecc": ecc, "valid": True, "warp": warp.tolist()},
        "raw": rawdiag,
        "jpeg": jpgdiag,
        "routes": routes,
    }


def strip_internal_summary_values(obj: dict) -> None:
    for p in obj["pairs"]:
        for route in p.get("routes", {}).values():
            for domain in ("linear", "code"):
                if domain in route:
                    route[domain].pop("gain_values_for_summary", None)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--pairs", nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    pairs = []
    for n in args.pairs:
        dng = args.dir / f"leica_m11_{n}.dng"
        jpg = args.dir / f"leica_m11_{n}.jpg"
        print(f"analyzing {n}", flush=True)
        p = analyze_pair(dng, jpg)
        pairs.append(p)
        if p["alignment"]["valid"]:
            print(
                f"  ISO={p['iso']:.0f} ECC={p['alignment']['ecc']:.4f} "
                f"H1 linear g50={p['routes']['H1']['linear']['gain_p50']:.4f} "
                f"code g50={p['routes']['H1']['code']['gain_p50']:.4f}",
                flush=True,
            )
        else:
            print(f"  alignment invalid ECC={p['alignment']['ecc']}", flush=True)

    valid = [p for p in pairs if p["alignment"]["valid"]]
    comparisons = {}
    for route in ("H0", "H1"):
        comparisons[route] = {}
        for domain in ("linear", "code"):
            comparisons[route][domain] = summarize_consistency(valid, route, domain)

    result = {
        "schema": "m11camera.r2.tone_domain_consistency.v1",
        "model_invariant": "Cout/(1.15*Cpre)=g(Ytone) if tone is RGB-scalar before/through CC1, gamma is Y-only, and tested JPEG domain is before final nonlinear RGB transfer",
        "recorded_standard_tone_gain_range": list(RECORDED_STANDARD_GAIN_RANGE),
        "bin_edges": BIN_EDGES.tolist(),
        "valid_pair_count": len(valid),
        "pair_count": len(pairs),
        "comparisons": comparisons,
        "pairs": pairs,
    }
    strip_internal_summary_values(result)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    print("\naggregate", flush=True)
    for route in ("H0", "H1"):
        for domain in ("linear", "code"):
            m = comparisons[route][domain]
            print(
                f"{route} {domain}: bins={m['eligible_bin_count']} "
                f"median_log_resid={m['scene_bin_log_abs_residual_median']} "
                f"g05/g50/g95={m['pooled_gain_p05']:.4f}/"
                f"{m['pooled_gain_p50']:.4f}/{m['pooled_gain_p95']:.4f}",
                flush=True,
            )


if __name__ == "__main__":
    main()
