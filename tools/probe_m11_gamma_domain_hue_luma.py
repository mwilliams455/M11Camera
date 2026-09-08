#!/usr/bin/env python3
"""Test M11 gamma/domain hypotheses using hue residual vs luminance.

The current reference renderer applies the recovered Leica gamma table to Y only
in the YCC-like domain.  That placement is explicitly an assumption.

A useful property lets us test the assumption before recovering the exact gamma
samples:

- the recorded tone stage is an RGB scalar, so it preserves chromaticity;
- CC1 is linear, so the scalar commutes through CC1;
- a Y-only gamma changes Y but not the Cb/Cr direction;
- symmetric Standard saturation changes chroma magnitude but not hue.

Therefore a pure ``scalar tone -> Y-only gamma -> symmetric chroma`` path should
not introduce a brightness-dependent Cb/Cr hue rotation.  A component/RGB
nonlinearity generally *does* break scale homogeneity: for otherwise similar
chromaticities, hue residual changes with brightness.

This probe controls chromaticity approximately by binning candidate pixels by:
- 12 pre-nonlinear Cb/Cr hue sectors;
- fixed chroma/luma-ratio bins (saturation proxy);
then measures the slope of candidate-vs-JPEG hue residual across one-stop luma
bins inside each hue/saturation cell.

Two JPEG observation domains are evaluated:
- ICC-managed, inverse-sRGB-OETF linear RGB;
- sRGB code values (positive control: the component sRGB OETF should create more
  brightness-dependent hue behavior than the linearized domain).

No gamma curve, tone curve, per-scene matrix or local correction is fitted.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import cv2
import numpy as np

import jpeg_icc_srgb
import probe_m11_pixel_chroma_fast as base

# Keep JPEG colour management canonical for every path in this probe.
base.read_jpeg = lambda p: jpeg_icc_srgb.read_jpeg_icc_to_linear_srgb(
    p, work_long=base.WORK_LONG
)

HUE_SECTORS = 12
SAT_RATIO_EDGES = np.array([0.035, 0.07, 0.14, 0.28, 0.56, 1.12], np.float64)
LUMA_EDGES = np.array([0.015625, 0.03125, 0.0625, 0.125, 0.25, 0.5, 1.0], np.float64)
MIN_BIN_POINTS = 120
MIN_CELL_LUMA_BINS = 3
MIN_CELL_STOP_SPAN = 1.25
MAX_POINTS_PER_PAIR_ROUTE = 120_000


def srgb_encode(x: np.ndarray) -> np.ndarray:
    x = np.maximum(np.asarray(x, np.float32), 0.0)
    return np.where(
        x <= 0.0031308,
        12.92 * x,
        1.055 * np.power(x, 1.0 / 2.4) - 0.055,
    ).astype(np.float32)


def angular_diff_deg(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    d = (a - b + np.pi) % (2.0 * np.pi) - np.pi
    return np.degrees(d)


def deterministic_subsample(arrays: dict[str, np.ndarray], nmax: int) -> dict[str, np.ndarray]:
    n = len(next(iter(arrays.values())))
    if n <= nmax:
        return arrays
    idx = np.linspace(0, n - 1, nmax, dtype=np.int64)
    return {k: v[idx] for k, v in arrays.items()}


def warp_candidate(candidate: np.ndarray, target_shape, warp: np.ndarray) -> np.ndarray:
    h, w = target_shape[:2]
    resized = cv2.resize(candidate.astype(np.float32), (w, h), interpolation=cv2.INTER_AREA)
    return cv2.warpAffine(
        resized,
        warp,
        (w, h),
        flags=cv2.INTER_LINEAR | cv2.WARP_INVERSE_MAP,
        borderMode=cv2.BORDER_CONSTANT,
        borderValue=0,
    )


def route_points(candidate_rgb: np.ndarray, jpeg_linear: np.ndarray) -> dict[str, np.ndarray]:
    cand_ycc = base.apply(candidate_rgb, base.YCC)
    jpg_code = srgb_encode(jpeg_linear)
    out_linear_ycc = base.apply(jpeg_linear, base.YCC)
    out_code_ycc = base.apply(jpg_code, base.YCC)

    y = cand_ycc[..., 0]
    cb = cand_ycc[..., 1]
    cr = cand_ycc[..., 2]
    c = np.hypot(cb, cr)
    hue = np.arctan2(cr, cb)
    sat_ratio = c / np.maximum(np.abs(y), 1.0e-6)

    out_lin_hue = np.arctan2(out_linear_ycc[..., 2], out_linear_ycc[..., 1])
    out_code_hue = np.arctan2(out_code_ycc[..., 2], out_code_ycc[..., 1])
    out_lin_c = np.hypot(out_linear_ycc[..., 1], out_linear_ycc[..., 2])
    out_code_c = np.hypot(out_code_ycc[..., 1], out_code_ycc[..., 2])

    # Avoid clipping, near-neutrals and alignment-sensitive borders.  The same
    # content mask is shared by linear/code observation domains.
    valid = (
        np.all(candidate_rgb > 0.003, axis=-1)
        & np.all(candidate_rgb < 0.98, axis=-1)
        & np.all(jpeg_linear > 0.002, axis=-1)
        & np.all(jpeg_linear < 0.97, axis=-1)
        & (y >= LUMA_EDGES[0])
        & (y <= LUMA_EDGES[-1])
        & (c > 0.008)
        & (out_lin_c > 0.008)
        & (out_code_c > 0.008)
        & (sat_ratio >= SAT_RATIO_EDGES[0])
        & (sat_ratio <= SAT_RATIO_EDGES[-1])
    )

    h, w = valid.shape
    margin = max(6, round(min(h, w) * 0.025))
    valid[:margin] = False
    valid[-margin:] = False
    valid[:, :margin] = False
    valid[:, -margin:] = False

    # Suppress high-gradient regions where sub-pixel RAW/JPEG registration and
    # different demosaicing/sharpening can dominate colour differences.
    out_luma = out_linear_ycc[..., 0].astype(np.float32)
    gx = cv2.Sobel(out_luma, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(out_luma, cv2.CV_32F, 0, 1, ksize=3)
    grad = np.hypot(gx, gy)
    finite_grad = grad[np.isfinite(grad)]
    grad_cut = float(np.percentile(finite_grad, 70)) if finite_grad.size else math.inf
    valid &= grad <= grad_cut

    arrays = {
        "y": y[valid].astype(np.float64),
        "hue": hue[valid].astype(np.float64),
        "sat_ratio": sat_ratio[valid].astype(np.float64),
        "residual_linear_deg": angular_diff_deg(hue[valid], out_lin_hue[valid]).astype(np.float64),
        "residual_code_deg": angular_diff_deg(hue[valid], out_code_hue[valid]).astype(np.float64),
    }
    arrays = deterministic_subsample(arrays, MAX_POINTS_PER_PAIR_ROUTE)
    arrays["gradient_cut"] = np.asarray([grad_cut], np.float64)
    arrays["valid_before_subsample"] = np.asarray([int(np.count_nonzero(valid))], np.int64)
    return arrays


def cell_trends(points: dict[str, np.ndarray], residual_key: str) -> list[dict]:
    y = points["y"]
    hue = points["hue"]
    sat = points["sat_ratio"]
    residual = points[residual_key]

    hue_sector = np.floor(((hue + np.pi) % (2.0 * np.pi)) / (2.0 * np.pi) * HUE_SECTORS).astype(int)
    hue_sector = np.clip(hue_sector, 0, HUE_SECTORS - 1)
    sat_bin = np.digitize(sat, SAT_RATIO_EDGES) - 1
    luma_bin = np.digitize(y, LUMA_EDGES) - 1

    results = []
    for hs in range(HUE_SECTORS):
        for sb in range(len(SAT_RATIO_EDGES) - 1):
            rows = []
            for lb in range(len(LUMA_EDGES) - 1):
                mask = (hue_sector == hs) & (sat_bin == sb) & (luma_bin == lb)
                n = int(np.count_nonzero(mask))
                if n < MIN_BIN_POINTS:
                    continue
                yy = y[mask]
                rr = residual[mask]
                rows.append({
                    "luma_bin": lb,
                    "n": n,
                    "log2_y_median": float(np.median(np.log2(yy))),
                    "y_median": float(np.median(yy)),
                    "residual_median_deg": float(np.median(rr)),
                    "residual_p25_deg": float(np.percentile(rr, 25)),
                    "residual_p75_deg": float(np.percentile(rr, 75)),
                })
            if len(rows) < MIN_CELL_LUMA_BINS:
                continue
            x = np.asarray([r["log2_y_median"] for r in rows], np.float64)
            z = np.asarray([r["residual_median_deg"] for r in rows], np.float64)
            span_stops = float(np.max(x) - np.min(x))
            if span_stops < MIN_CELL_STOP_SPAN:
                continue
            slope, intercept = np.polyfit(x, z, 1)
            pred = slope * x + intercept
            ss_res = float(np.sum((z - pred) ** 2))
            ss_tot = float(np.sum((z - np.mean(z)) ** 2))
            r2 = 1.0 - ss_res / ss_tot if ss_tot > 1.0e-12 else 0.0
            results.append({
                "hue_sector": hs,
                "hue_center_deg": float(-180.0 + (hs + 0.5) * 360.0 / HUE_SECTORS),
                "sat_bin": sb,
                "sat_lo": float(SAT_RATIO_EDGES[sb]),
                "sat_hi": float(SAT_RATIO_EDGES[sb + 1]),
                "luma_bin_count": len(rows),
                "luma_span_stops": span_stops,
                "slope_deg_per_stop": float(slope),
                "abs_slope_deg_per_stop": float(abs(slope)),
                "residual_median_span_deg": float(np.max(z) - np.min(z)),
                "fit_r2": float(r2),
                "bins": rows,
            })
    return results


def summarize_trends(trends: list[dict]) -> dict:
    if not trends:
        return {"cell_count": 0}
    slopes = np.asarray([t["slope_deg_per_stop"] for t in trends], np.float64)
    abs_slopes = np.abs(slopes)
    spans = np.asarray([t["residual_median_span_deg"] for t in trends], np.float64)
    r2 = np.asarray([t["fit_r2"] for t in trends], np.float64)
    return {
        "cell_count": len(trends),
        "median_abs_slope_deg_per_stop": float(np.median(abs_slopes)),
        "mean_abs_slope_deg_per_stop": float(np.mean(abs_slopes)),
        "p75_abs_slope_deg_per_stop": float(np.percentile(abs_slopes, 75)),
        "p90_abs_slope_deg_per_stop": float(np.percentile(abs_slopes, 90)),
        "median_residual_span_deg": float(np.median(spans)),
        "p90_residual_span_deg": float(np.percentile(spans, 90)),
        "median_fit_r2": float(np.median(r2)),
        "cells_abs_slope_gt_1deg_per_stop": int(np.count_nonzero(abs_slopes > 1.0)),
        "cells_abs_slope_gt_2deg_per_stop": int(np.count_nonzero(abs_slopes > 2.0)),
        "positive_slope_count": int(np.count_nonzero(slopes > 0)),
        "negative_slope_count": int(np.count_nonzero(slopes < 0)),
    }


def analyze_pair(dng: Path, jpg: Path) -> dict:
    meta = base.metadata(dng)
    raw, rawdiag = base.read_camera_rgb(dng)
    jpg_linear, jpgdiag = base.read_jpeg(jpg)
    matrices, bridge = base.route_matrices(meta)

    h1 = base.apply(raw, matrices["H1"])
    _, warp, ecc, valid = base.align(jpg_linear, h1)
    out = {
        "stem": dng.stem,
        "iso": meta["iso"],
        "alignment": {"ecc": ecc, "valid": bool(valid), "warp": warp.tolist()},
        "bridge": bridge,
        "raw": rawdiag,
        "jpeg": jpgdiag,
        "routes": {},
    }
    if not valid:
        return out

    for route in ("H0", "H1", "DNG"):
        cand = base.apply(raw, matrices[route])
        aligned = warp_candidate(cand, jpg_linear.shape, warp)
        pts = route_points(aligned, jpg_linear)
        route_obj = {
            "sample_count": int(pts["y"].size),
            "valid_before_subsample": int(pts["valid_before_subsample"][0]),
            "gradient_cut": float(pts["gradient_cut"][0]),
        }
        for domain, key in (
            ("linear", "residual_linear_deg"),
            ("code", "residual_code_deg"),
        ):
            trends = cell_trends(pts, key)
            route_obj[domain] = {
                "summary": summarize_trends(trends),
                "cells": trends,
            }
        out["routes"][route] = route_obj
    return out


def pooled_points_for_route(pair_inputs: list[tuple[np.ndarray, np.ndarray, np.ndarray]], route: str):
    # Unused placeholder intentionally omitted from results; pooled aggregate is
    # built from per-pair cell slopes so no one high-resolution scene dominates.
    raise NotImplementedError


def aggregate_pair_summaries(pairs: list[dict], route: str, domain: str) -> dict:
    vals = []
    for p in pairs:
        if not p["alignment"]["valid"]:
            continue
        s = p["routes"][route][domain]["summary"]
        if s.get("cell_count", 0) <= 0:
            continue
        vals.append({"stem": p["stem"], **s})
    if not vals:
        return {"pair_count": 0, "pairs": []}

    def arr(key):
        return np.asarray([v[key] for v in vals], np.float64)

    return {
        "pair_count": len(vals),
        "median_of_pair_median_abs_slopes_deg_per_stop": float(np.median(arr("median_abs_slope_deg_per_stop"))),
        "mean_of_pair_median_abs_slopes_deg_per_stop": float(np.mean(arr("median_abs_slope_deg_per_stop"))),
        "median_of_pair_p90_abs_slopes_deg_per_stop": float(np.median(arr("p90_abs_slope_deg_per_stop"))),
        "median_of_pair_median_residual_spans_deg": float(np.median(arr("median_residual_span_deg"))),
        "pairs": vals,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--pairs", nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    pairs = []
    for n in args.pairs:
        print(f"analyzing {n}", flush=True)
        p = analyze_pair(
            args.dir / f"leica_m11_{n}.dng",
            args.dir / f"leica_m11_{n}.jpg",
        )
        pairs.append(p)
        if p["alignment"]["valid"]:
            h1lin = p["routes"]["H1"]["linear"]["summary"]
            h1code = p["routes"]["H1"]["code"]["summary"]
            print(
                f"  ISO={p['iso']:.0f} ECC={p['alignment']['ecc']:.4f} "
                f"H1 linear cells={h1lin.get('cell_count',0)} "
                f"med|slope|={h1lin.get('median_abs_slope_deg_per_stop')} "
                f"code={h1code.get('median_abs_slope_deg_per_stop')}",
                flush=True,
            )

    aggregate = {}
    for route in ("H0", "H1", "DNG"):
        aggregate[route] = {}
        for domain in ("linear", "code"):
            aggregate[route][domain] = aggregate_pair_summaries(pairs, route, domain)

    # Positive-control ratio: if inverse sRGB OETF is doing useful work, H1 code
    # space should ordinarily show a larger luma-dependent hue slope than H1 linear.
    lin = aggregate["H1"]["linear"].get("median_of_pair_median_abs_slopes_deg_per_stop")
    code = aggregate["H1"]["code"].get("median_of_pair_median_abs_slopes_deg_per_stop")
    ratio = (code / lin) if lin and code is not None else None

    result = {
        "schema": "m11camera.r2.gamma_domain_hue_luma.v1",
        "hypothesis": (
            "Y-only gamma plus scalar tone and symmetric chroma should preserve Cb/Cr hue; "
            "brightness-dependent residual within fixed hue/saturation cells argues for an "
            "additional component/RGB nonlinearity or other luma-dependent hue stage."
        ),
        "positive_control": (
            "sRGB code-space residual should have stronger luminance dependence than ICC-managed "
            "linear-sRGB residual because the sRGB OETF is component-wise nonlinear."
        ),
        "hue_sectors": HUE_SECTORS,
        "sat_ratio_edges": SAT_RATIO_EDGES.tolist(),
        "luma_edges": LUMA_EDGES.tolist(),
        "valid_pair_count": sum(p["alignment"]["valid"] for p in pairs),
        "pair_count": len(pairs),
        "aggregate": aggregate,
        "h1_code_to_linear_median_slope_ratio": ratio,
        "pairs": pairs,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    print("\nAGGREGATE", flush=True)
    for route in ("H0", "H1", "DNG"):
        for domain in ("linear", "code"):
            a = aggregate[route][domain]
            print(
                route,
                domain,
                "pairs", a.get("pair_count"),
                "median(pair median |slope|)", a.get("median_of_pair_median_abs_slopes_deg_per_stop"),
                "median(pair p90 |slope|)", a.get("median_of_pair_p90_abs_slopes_deg_per_stop"),
                flush=True,
            )
    print("H1 code/linear slope ratio", ratio, flush=True)


if __name__ == "__main__":
    main()
