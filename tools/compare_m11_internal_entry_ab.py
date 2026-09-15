#!/usr/bin/env python3
"""Diagnostic-only A/B for the M11 XYZ-D50 -> internal working-space seam.

A (frozen historical entry):
    XYZ D50 -> provisional M11 reference basis -> historical/static CC0
B (firmware-domain entry):
    XYZ D50 -> fixed firmware PCS_TO_INTERNAL matrix K

Both branches then execute the exact same downstream reference stages:
    tone -> CC1 -> YCC -> gamma(Y) -> mode chroma -> inverse YCC -> clamp

This tool deliberately does not mutate RENDER1H or the controlled renderer.
It is intended to answer one bounded question on one identical Xiaomi DNG/XYZ buffer:
Does replacing the provisional basis + historical CC0 pair with direct K produce the
~0.05 EV / small chromatic residual predicted by the firmware closure?
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from renderer.m11_core import reference_basis as m11_basis
from renderer.reference import leica_m11_reference_renderer as m11_reference
from renderer.source_adapter import dng_dual_illuminant as dng_source
from tools import m11_internal_entry_reference as internal_entry
from tools import render_xiaomi_m11_controlled as controlled


HIST_BINS = 64
HIST_MIN = 0.0
HIST_MAX = 1.0


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def _flatten3(values: np.ndarray) -> np.ndarray:
    arr = np.asarray(values, dtype=np.float64)
    if arr.shape[-1] != 3:
        raise ValueError("stage data must have three channels")
    return arr.reshape(-1, 3)


def _histogram(values: np.ndarray) -> dict[str, Any]:
    arr = _flatten3(values)
    edges = np.linspace(HIST_MIN, HIST_MAX, HIST_BINS + 1)
    counts = []
    for c in range(3):
        h, _ = np.histogram(arr[:, c], bins=edges)
        counts.append(h.astype(np.int64).tolist())
    return {
        "range": [HIST_MIN, HIST_MAX],
        "bins": HIST_BINS,
        "edges": edges.tolist(),
        "channel_counts": counts,
        "below_range": np.sum(arr < HIST_MIN, axis=0).astype(np.int64).tolist(),
        "above_range": np.sum(arr > HIST_MAX, axis=0).astype(np.int64).tolist(),
    }


def _percentiles(arr: np.ndarray) -> dict[str, Any]:
    p = np.percentile(arr, [1.0, 50.0, 95.0, 99.0], axis=0)
    return {"p01": p[0].tolist(), "p50": p[1].tolist(), "p95": p[2].tolist(), "p99": p[3].tolist()}


def _rgb_stage_stats(values: np.ndarray) -> dict[str, Any]:
    arr = _flatten3(values)
    luma = arr @ m11_reference.TONE_Y
    lp = np.percentile(luma, [1.0, 50.0, 95.0, 99.0])
    return {
        "samples": int(arr.shape[0]),
        "mean": np.mean(arr, axis=0).tolist(),
        "min": np.min(arr, axis=0).tolist(),
        **_percentiles(arr),
        "max": np.max(arr, axis=0).tolist(),
        "fraction_below_0": float(np.mean(arr < 0.0)),
        "fraction_above_1": float(np.mean(arr > 1.0)),
        "pixels_any_below_0": float(np.mean(np.any(arr < 0.0, axis=1))),
        "pixels_any_above_1": float(np.mean(np.any(arr > 1.0, axis=1))),
        "luma": {
            "mean": float(np.mean(luma)),
            "min": float(np.min(luma)),
            "p01": float(lp[0]),
            "p50": float(lp[1]),
            "p95": float(lp[2]),
            "p99": float(lp[3]),
            "max": float(np.max(luma)),
        },
        "histogram": _histogram(arr),
    }


def _ycc_stage_stats(values: np.ndarray) -> dict[str, Any]:
    arr = _flatten3(values)
    y = arr[:, 0]
    yp = np.percentile(y, [1.0, 50.0, 95.0, 99.0])
    return {
        "samples": int(arr.shape[0]),
        "mean": np.mean(arr, axis=0).tolist(),
        "min": np.min(arr, axis=0).tolist(),
        **_percentiles(arr),
        "max": np.max(arr, axis=0).tolist(),
        "y": {
            "mean": float(np.mean(y)),
            "min": float(np.min(y)),
            "p01": float(yp[0]),
            "p50": float(yp[1]),
            "p95": float(yp[2]),
            "p99": float(yp[3]),
            "max": float(np.max(y)),
        },
        "histogram": _histogram(arr),
    }


def _run_downstream(post_cc0: np.ndarray, tables: m11_reference.Tables, mode: str) -> tuple[np.ndarray, dict[str, Any]]:
    cfg = m11_reference.MODE_CONFIG[mode]
    post_cc0 = np.asarray(post_cc0, dtype=np.float64)
    post_tone = m11_reference.apply_tone_luma(post_cc0, tables, cfg["contrast"])
    post_cc1 = m11_reference.apply_matrix(post_tone, tables.cc1)
    ycc = m11_reference.apply_matrix(post_cc1, m11_reference.YCC_M)

    post_gamma_ycc = ycc.copy()
    y = np.clip(post_gamma_ycc[..., 0], 0.0, 1.0)
    post_gamma_ycc[..., 0] = np.interp(y, tables.gamma_x, tables.gamma_y)

    post_chroma_ycc = post_gamma_ycc.copy()
    post_chroma_ycc[..., 1] *= cfg["chroma"]
    post_chroma_ycc[..., 2] *= cfg["chroma"]

    preclamp = m11_reference.ycc_to_rgb(post_chroma_ycc)
    output = np.clip(preclamp, 0.0, 1.0)
    diag = {
        "post_cc0_internal": _rgb_stage_stats(post_cc0),
        "post_tone": _rgb_stage_stats(post_tone),
        "post_cc1": _rgb_stage_stats(post_cc1),
        "post_ycc": _ycc_stage_stats(ycc),
        "post_gamma_ycc": _ycc_stage_stats(post_gamma_ycc),
        "post_chroma_ycc": _ycc_stage_stats(post_chroma_ycc),
        "preclamp_rgb": _rgb_stage_stats(preclamp),
        "output_rgb": _rgb_stage_stats(output),
    }
    return output, diag


def _delta_stats(a: np.ndarray, b: np.ndarray) -> dict[str, Any]:
    aa = _flatten3(a)
    bb = _flatten3(b)
    d = bb - aa
    ad = np.abs(d)
    scalar_abs = ad.reshape(-1)
    dp = np.percentile(scalar_abs, [50.0, 95.0, 99.0, 99.9])
    luma_a = aa @ m11_reference.TONE_Y
    luma_b = bb @ m11_reference.TONE_Y
    luma_d = luma_b - luma_a
    mse = float(np.mean(d * d))
    psnr = math.inf if mse == 0.0 else float(10.0 * math.log10(1.0 / mse))
    return {
        "signed_mean_per_channel": np.mean(d, axis=0).tolist(),
        "mean_abs_per_channel": np.mean(ad, axis=0).tolist(),
        "max_abs_per_channel": np.max(ad, axis=0).tolist(),
        "abs_scalar_p50": float(dp[0]),
        "abs_scalar_p95": float(dp[1]),
        "abs_scalar_p99": float(dp[2]),
        "abs_scalar_p999": float(dp[3]),
        "abs_scalar_max": float(np.max(scalar_abs)),
        "fraction_abs_gt_1_code_8bit": float(np.mean(scalar_abs > (1.0 / 255.0))),
        "fraction_abs_gt_2_code_8bit": float(np.mean(scalar_abs > (2.0 / 255.0))),
        "mse": mse,
        "psnr_db": psnr,
        "luma_signed_mean": float(np.mean(luma_d)),
        "luma_abs_mean": float(np.mean(np.abs(luma_d))),
        "luma_abs_max": float(np.max(np.abs(luma_d))),
    }


def compare_xyz_buffer(xyz_d50: np.ndarray, tables: m11_reference.Tables, mode: str = "standard") -> dict[str, Any]:
    """Run the isolated A/B from one identical XYZ-D50 buffer."""
    xyz = np.asarray(xyz_d50, dtype=np.float64)
    if xyz.shape[-1] != 3:
        raise ValueError("XYZ buffer must have three channels")

    old_reference = m11_basis.apply_xyz_d50_to_m11_reference(xyz)
    old_post_cc0 = m11_reference.apply_matrix(old_reference, tables.cc0)
    direct_post_cc0 = internal_entry.xyz_d50_to_internal(xyz)

    old_output, old_stages = _run_downstream(old_post_cc0, tables, mode)
    direct_output, direct_stages = _run_downstream(direct_post_cc0, tables, mode)

    old_check = m11_reference.render(
        old_reference,
        tables,
        mode,
        use_cc0=True,
        use_tone=True,
        use_cc1=True,
        use_gamma=True,
        use_chroma=True,
        clamp=True,
    )
    direct_check = m11_reference.render(
        direct_post_cc0,
        tables,
        mode,
        use_cc0=False,
        use_tone=True,
        use_cc1=True,
        use_gamma=True,
        use_chroma=True,
        clamp=True,
    )
    old_parity = float(np.max(np.abs(old_output - old_check)))
    direct_parity = float(np.max(np.abs(direct_output - direct_check)))
    if old_parity > 1e-12 or direct_parity > 1e-12:
        raise RuntimeError(f"A/B downstream parity gate failed: old={old_parity} direct={direct_parity}")

    old_luma = _flatten3(old_post_cc0) @ m11_reference.TONE_Y
    direct_luma = _flatten3(direct_post_cc0) @ m11_reference.TONE_Y
    positive = (old_luma > 1e-12) & (direct_luma > 1e-12)
    empirical_ev = None
    if np.any(positive):
        empirical_ev = float(np.median(np.log2(direct_luma[positive] / old_luma[positive])))

    return {
        "schema": "m11camera.internal_entry_ab.v1",
        "mode": mode,
        "boundary": "identical linear white-balanced XYZ D50 buffer",
        "branch_a": "provisional_reference_basis_then_historical_static_CC0",
        "branch_b": "firmware_PCS_TO_INTERNAL_K_direct_no_extra_CC0",
        "downstream_identical": ["tone", "CC1", "YCC", "gamma_Y", "mode_chroma", "inverse_YCC", "clamp"],
        "old_branch": old_stages,
        "direct_k_branch": direct_stages,
        "post_cc0_delta": _delta_stats(old_post_cc0, direct_post_cc0),
        "output_delta": _delta_stats(old_output, direct_output),
        "empirical_post_cc0_median_luma_ev_direct_vs_old": empirical_ev,
        "renderer_parity_gate": {
            "old_max_abs": old_parity,
            "direct_k_max_abs": direct_parity,
            "tolerance": 1e-12,
            "passed": True,
        },
        "outputs": {"old": old_output, "direct_k": direct_output},
    }


def _sample_xyz(rgb16: np.ndarray, source_transform: np.ndarray, max_samples: int) -> tuple[np.ndarray, int]:
    h, w = rgb16.shape[:2]
    stride = max(1, int(math.ceil(math.sqrt((h * w) / max_samples))))
    camera = rgb16[::stride, ::stride].astype(np.float64) / 65535.0
    xyz = dng_source.apply_camera_to_xyz(camera, source_transform)
    return xyz, stride


def _render_full_ab(
    rgb16: np.ndarray,
    source_transform: np.ndarray,
    tables: m11_reference.Tables,
    mode: str,
    chunk_rows: int,
) -> tuple[np.ndarray, np.ndarray]:
    h, w = rgb16.shape[:2]
    old8 = np.empty((h, w, 3), dtype=np.uint8)
    direct8 = np.empty((h, w, 3), dtype=np.uint8)
    for y0 in range(0, h, chunk_rows):
        y1 = min(h, y0 + chunk_rows)
        camera = rgb16[y0:y1].astype(np.float64) / 65535.0
        xyz = dng_source.apply_camera_to_xyz(camera, source_transform)
        result = compare_xyz_buffer(xyz, tables, mode)
        old = np.asarray(result["outputs"]["old"])
        direct = np.asarray(result["outputs"]["direct_k"])
        old8[y0:y1] = np.clip(np.rint(old * 255.0), 0.0, 255.0).astype(np.uint8)
        direct8[y0:y1] = np.clip(np.rint(direct * 255.0), 0.0, 255.0).astype(np.uint8)
    return old8, direct8


def _strip_outputs(result: dict[str, Any]) -> dict[str, Any]:
    out = dict(result)
    out.pop("outputs", None)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Same-DNG diagnostic A/B: frozen old M11 entry vs direct firmware K")
    ap.add_argument("input", type=Path)
    ap.add_argument("--data-dir", type=Path, default=m11_reference.DEFAULT_DATA)
    ap.add_argument("--mode", choices=sorted(m11_reference.MODE_CONFIG), default="standard")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--expected-dng-sha256")
    ap.add_argument("--decode-scale", choices=["auto", "full", "half"], default="auto")
    ap.add_argument("--chunk-rows", type=int, default=256)
    ap.add_argument("--max-samples", type=int, default=120_000)
    ap.add_argument("--jpeg-quality", type=int, default=97)
    args = ap.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input DNG not found: {args.input}")
    if args.chunk_rows <= 0 or args.max_samples <= 0:
        raise SystemExit("--chunk-rows and --max-samples must be > 0")

    source_sha = controlled.sha256_file(args.input)
    if args.expected_dng_sha256 and source_sha.lower() != args.expected_dng_sha256.lower():
        raise SystemExit(f"DNG SHA256 mismatch: got {source_sha}, expected {args.expected_dng_sha256}")

    record = controlled.exiftool_record(args.input)
    meta = controlled.parse_dng_metadata(record)
    source_result, source_diag = controlled.build_source_transform(meta)
    tables = m11_reference.load_tables(args.data_dir)
    rgb16, decode_diag = controlled.decode_camera_rgb(args.input, args.decode_scale)

    xyz_sample, stride = _sample_xyz(rgb16, source_result.camera_to_xyz_d50, args.max_samples)
    sample_result = compare_xyz_buffer(xyz_sample, tables, args.mode)
    matrix_prediction = internal_entry.compare_source_entries(source_result.camera_to_xyz_d50)

    old8, direct8 = _render_full_ab(
        rgb16,
        source_result.camera_to_xyz_d50,
        tables,
        args.mode,
        args.chunk_rows,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.input.stem
    old_path = args.out_dir / f"{stem}_M11_ENTRY_OLD.jpg"
    direct_path = args.out_dir / f"{stem}_M11_ENTRY_DIRECT_K.jpg"
    diag_path = args.out_dir / f"{stem}_M11_ENTRY_AB.json"
    controlled.save_jpeg(old_path, old8, args.jpeg_quality, "srgb-tag")
    controlled.save_jpeg(direct_path, direct8, args.jpeg_quality, "srgb-tag")

    full8_delta = direct8.astype(np.int16) - old8.astype(np.int16)
    diagnostics = {
        **_strip_outputs(sample_result),
        "source_dng": {
            "path": str(args.input),
            "sha256": source_sha,
            "expected_sha256": args.expected_dng_sha256,
        },
        "source_bridge": source_diag,
        "decode": decode_diag,
        "sample_stride": stride,
        "matrix_prediction": {
            "best_scalar_old_to_direct": matrix_prediction.best_scalar_old_to_direct,
            "direct_relative_ev": matrix_prediction.direct_relative_ev,
            "max_abs_residual_after_scalar": matrix_prediction.max_abs_residual_after_scalar,
            "rms_residual_after_scalar": matrix_prediction.rms_residual_after_scalar,
            "old_camera_to_internal": matrix_prediction.old_camera_to_internal.tolist(),
            "direct_camera_to_internal": matrix_prediction.direct_camera_to_internal.tolist(),
        },
        "full_frame_8bit_delta": {
            "signed_mean_per_channel_codes": np.mean(full8_delta.reshape(-1, 3), axis=0).tolist(),
            "mean_abs_codes": float(np.mean(np.abs(full8_delta))),
            "p95_abs_codes": float(np.percentile(np.abs(full8_delta), 95.0)),
            "p99_abs_codes": float(np.percentile(np.abs(full8_delta), 99.0)),
            "max_abs_codes": int(np.max(np.abs(full8_delta))),
            "fraction_pixels_identical": float(np.mean(np.all(full8_delta == 0, axis=2))),
        },
        "outputs": {
            "old_jpeg": str(old_path),
            "direct_k_jpeg": str(direct_path),
            "old_sha256": controlled.sha256_file(old_path),
            "direct_k_sha256": controlled.sha256_file(direct_path),
        },
        "guardrails": {
            "renderer_mutated": False,
            "m11_colorspec_reapplied_to_xiaomi": False,
            "additional_wb": False,
            "hdr": False,
            "local_tone_mapping": False,
            "third_sro": False,
        },
    }
    diag_path.write_text(json.dumps(diagnostics, indent=2, default=_jsonable) + "\n")
    print(json.dumps({"old": str(old_path), "direct_k": str(direct_path), "diagnostics": str(diag_path)}, indent=2))


if __name__ == "__main__":
    main()
