#!/usr/bin/env python3
"""Controlled Xiaomi 15 Ultra DNG -> frozen Leica M11 reference JPEG runner.

This is a validation harness, not an APK renderer and not a visual-tuning path.
It keeps the Xiaomi source characterization, M11 input bridge, and frozen
firmware-derived target renderer as distinct stages:

    Xiaomi DNG
      -> LibRaw/rawpy linear demosaic in *camera RGB* with unity WB
      -> DNG dual-illuminant camera RGB -> XYZ D50 source transform
      -> provisional XYZ D50 -> M11 Standard-A reference-basis bridge
      -> frozen M11 CC0 -> tone -> CC1 -> YC -> gamma(Y) -> chroma model
      -> high-quality JPEG + diagnostics JSON

No HDR, local tone mapping, highlight reconstruction, Cobalt profile, or visual
LUT correction is introduced here.  The current Y-after-YC gamma placement is
used exactly as the frozen reference renderer defines it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from renderer.m11_core import reference_basis as m11_basis
from renderer.reference import leica_m11_reference_renderer as m11_reference
from renderer.source_adapter import dng_dual_illuminant as dng_source

HISTORICAL_MAIN = (
    ROOT / "research" / "xiaomi" / "xiaomi15ultra_main_native_source_characterization_v1.json"
)
TABLE_FILENAMES = (
    "category3_CC0_candidate.json",
    "category13_CC1_candidate.json",
    "tone_q12_reconstructed_curves.csv",
    "gamma_4096_high_nibble_first.csv",
)


@dataclass(frozen=True)
class DngMetadata:
    record: dict[str, Any]
    neutral: np.ndarray
    color_matrix1: np.ndarray
    color_matrix2: np.ndarray
    calibration1: np.ndarray
    calibration2: np.ndarray
    calibration1_defaulted_identity: bool
    calibration2_defaulted_identity: bool
    forward_matrix1: np.ndarray
    forward_matrix2: np.ndarray
    illuminant1: int
    illuminant2: int


def suffix_lookup(obj: dict[str, Any], suffix: str) -> Any | None:
    target = suffix.lower()
    values = [v for k, v in obj.items() if k.split(":")[-1].lower() == target]
    for value in values:
        if value not in (None, "", []):
            return value
    return values[0] if values else None


def parse_numbers(value: Any, expected: int | None = None) -> np.ndarray:
    if value is None:
        raise ValueError("numeric value is missing")
    if isinstance(value, (int, float, np.integer, np.floating)):
        nums = [float(value)]
    elif isinstance(value, (list, tuple)):
        nums = []
        for item in value:
            if isinstance(item, (list, tuple)):
                nums.extend(float(v) for v in item)
            else:
                nums.append(float(item))
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


def _required(record: dict[str, Any], name: str) -> Any:
    value = suffix_lookup(record, name)
    if value in (None, "", []):
        raise ValueError(f"required DNG metadata tag {name} is missing")
    return value


def _matrix(record: dict[str, Any], name: str) -> np.ndarray:
    return parse_numbers(_required(record, name), 9).reshape(3, 3)


def _calibration_matrix(record: dict[str, Any], name: str) -> tuple[np.ndarray, bool]:
    value = suffix_lookup(record, name)
    if value in (None, "", []):
        # DNG CameraCalibration is optional; identity is the neutral/default case.
        return np.eye(3, dtype=np.float64), True
    return parse_numbers(value, 9).reshape(3, 3), False


def exiftool_record(path: Path) -> dict[str, Any]:
    exe = shutil.which("exiftool")
    if not exe:
        raise RuntimeError(
            "exiftool is required for controlled DNG metadata extraction; install it and retry"
        )
    proc = subprocess.run(
        [exe, "-j", "-n", "-G1", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    records = json.loads(proc.stdout)
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise RuntimeError("unexpected exiftool JSON result")
    return records[0]


def parse_dng_metadata(record: dict[str, Any]) -> DngMetadata:
    cal1, cal1_default = _calibration_matrix(record, "CameraCalibration1")
    cal2, cal2_default = _calibration_matrix(record, "CameraCalibration2")
    return DngMetadata(
        record=record,
        neutral=parse_numbers(_required(record, "AsShotNeutral"), 3),
        color_matrix1=_matrix(record, "ColorMatrix1"),
        color_matrix2=_matrix(record, "ColorMatrix2"),
        calibration1=cal1,
        calibration2=cal2,
        calibration1_defaulted_identity=cal1_default,
        calibration2_defaulted_identity=cal2_default,
        forward_matrix1=_matrix(record, "ForwardMatrix1"),
        forward_matrix2=_matrix(record, "ForwardMatrix2"),
        illuminant1=int(parse_scalar(_required(record, "CalibrationIlluminant1"))),
        illuminant2=int(parse_scalar(_required(record, "CalibrationIlluminant2"))),
    )


def sha256_file(path: Path, chunk_bytes: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def metadata_diagnostics(meta: DngMetadata) -> dict[str, Any]:
    r = meta.record

    def simple(name: str) -> Any:
        value = suffix_lookup(r, name)
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    return {
        "make": simple("Make"),
        "model": simple("Model"),
        "unique_camera_model": simple("UniqueCameraModel"),
        "lens_model": simple("LensModel"),
        "focal_length": simple("FocalLength"),
        "focal_length_35mm": simple("FocalLengthIn35mmFormat"),
        "iso": simple("ISO"),
        "exposure_time": simple("ExposureTime"),
        "aperture": simple("FNumber"),
        "black_level": simple("BlackLevel"),
        "white_level": simple("WhiteLevel"),
        "as_shot_neutral": meta.neutral.tolist(),
        "color_matrix1": meta.color_matrix1.tolist(),
        "color_matrix2": meta.color_matrix2.tolist(),
        "camera_calibration1": meta.calibration1.tolist(),
        "camera_calibration2": meta.calibration2.tolist(),
        "camera_calibration1_defaulted_identity": meta.calibration1_defaulted_identity,
        "camera_calibration2_defaulted_identity": meta.calibration2_defaulted_identity,
        "forward_matrix1": meta.forward_matrix1.tolist(),
        "forward_matrix2": meta.forward_matrix2.tolist(),
        "calibration_illuminant1": meta.illuminant1,
        "calibration_illuminant2": meta.illuminant2,
        "matrix_convention": "DNG ColorMatrix XYZ_to_reference_camera; ForwardMatrix normalization only",
    }


def build_source_transform(meta: DngMetadata) -> tuple[dng_source.DualIlluminantResult, dict[str, Any]]:
    result = dng_source.build_dual_illuminant_transform(
        meta.illuminant1,
        meta.illuminant2,
        meta.calibration1,
        meta.calibration2,
        meta.color_matrix1,
        meta.color_matrix2,
        meta.forward_matrix1,
        meta.forward_matrix2,
        meta.neutral,
    )

    xyz_to_camera1 = meta.calibration1 @ meta.color_matrix1
    xyz_to_camera2 = meta.calibration2 @ meta.color_matrix2
    xyz_to_camera = dng_source.lerp(
        xyz_to_camera1, xyz_to_camera2, result.interpolation_factor
    )
    neutral_xyz = np.linalg.inv(xyz_to_camera) @ meta.neutral
    scene_white_xy = dng_source.cie_xy_from_xyz(neutral_xyz)
    scene_cct = dng_source.mccamy_cct(*scene_white_xy)

    diag = {
        "name": "dng-native-v1",
        "interchange_space": "linear_scene_referred_XYZ_D50",
        "interpolation_factor_cm1_to_cm2": result.interpolation_factor,
        "reference_neutral": result.reference_neutral.tolist(),
        "camera_to_xyz_d50": result.camera_to_xyz_d50.tolist(),
        "estimated_scene_white_xy": list(scene_white_xy),
        "estimated_scene_cct_mccamy_k": scene_cct,
        "live_neutral_white_balance_folded_into_transform": True,
        "additional_downstream_source_wb": False,
    }
    return result, diag


def compare_historical_main(meta: DngMetadata, path: Path = HISTORICAL_MAIN) -> dict[str, Any]:
    if not path.exists():
        return {"available": False, "reason": f"missing {path}"}
    ref = json.loads(path.read_text())
    expected_cm1 = np.asarray(ref["color_matrix_d65"], dtype=np.float64)
    expected_cm2 = np.asarray(ref["color_matrix_A"], dtype=np.float64)
    expected_fm = np.asarray(ref["forward_matrix_raw_both_illuminants"], dtype=np.float64)

    deltas = {
        "color_matrix1_max_abs": float(np.max(np.abs(meta.color_matrix1 - expected_cm1))),
        "color_matrix2_max_abs": float(np.max(np.abs(meta.color_matrix2 - expected_cm2))),
        "forward_matrix1_max_abs": float(np.max(np.abs(meta.forward_matrix1 - expected_fm))),
        "forward_matrix2_max_abs": float(np.max(np.abs(meta.forward_matrix2 - expected_fm))),
    }
    illum_match = (
        meta.illuminant1 == int(ref["calibration_illuminants"]["1"]["dng_code"])
        and meta.illuminant2 == int(ref["calibration_illuminants"]["2"]["dng_code"])
    )
    tol = 1e-7
    matrix_match = all(v <= tol for v in deltas.values())
    return {
        "available": True,
        "reference_evidence_class": ref.get("evidence_class"),
        "tolerance": tol,
        "illuminants_match": illum_match,
        "static_matrices_match": matrix_match,
        "historical_main_characterization_match": bool(illum_match and matrix_match),
        "max_abs_deltas": deltas,
        "interpretation": (
            "match supports continuity with the historical main-sensor characterization; "
            "it does not independently prove physical camera identity"
        ),
    }


def _namedtuple_dict(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if hasattr(value, "_asdict"):
        return {k: _jsonable(v) for k, v in value._asdict().items()}
    return None


def decode_camera_rgb(path: Path, decode_scale: str) -> tuple[np.ndarray, dict[str, Any]]:
    try:
        import rawpy
    except ImportError as exc:
        raise RuntimeError("rawpy is required to decode the DNG; install rawpy and retry") from exc

    with rawpy.imread(str(path)) as raw:
        sizes = raw.sizes
        long_edge = max(int(sizes.width), int(sizes.height))
        if decode_scale == "auto":
            half_size = long_edge > 6000
        elif decode_scale == "half":
            half_size = True
        else:
            half_size = False

        params = {
            "demosaic_algorithm": rawpy.DemosaicAlgorithm.AHD,
            "half_size": half_size,
            "four_color_rgb": False,
            "use_camera_wb": False,
            "use_auto_wb": False,
            "user_wb": [1.0, 1.0, 1.0, 1.0],
            "output_color": rawpy.ColorSpace.raw,
            "output_bps": 16,
            "no_auto_scale": False,
            "no_auto_bright": True,
            "adjust_maximum_thr": 0.0,
            "bright": 1.0,
            "highlight_mode": rawpy.HighlightMode.Clip,
            "gamma": (1.0, 1.0),
        }
        rgb16 = raw.postprocess(**params)
        if rgb16.ndim != 3 or rgb16.shape[-1] != 3 or rgb16.dtype != np.uint16:
            raise RuntimeError(
                f"expected uint16 3-channel camera RGB from rawpy, got {rgb16.shape} {rgb16.dtype}"
            )

        color_desc = raw.color_desc
        if isinstance(color_desc, bytes):
            color_desc = color_desc.decode("ascii", errors="replace")
        raw_pattern = raw.raw_pattern.tolist() if raw.raw_pattern is not None else None
        camera_white = raw.camera_white_level_per_channel
        if camera_white is not None:
            camera_white = [float(v) for v in camera_white]
        diag = {
            "backend": "rawpy/LibRaw",
            "rawpy_version": getattr(rawpy, "__version__", None),
            "demosaic_algorithm": "AHD",
            "decode_scale_requested": decode_scale,
            "half_size_used": half_size,
            "source_visible_long_edge": long_edge,
            "output_shape": list(rgb16.shape),
            "output_dtype": str(rgb16.dtype),
            "output_color_space": "raw camera RGB",
            "white_balance": "unity [1,1,1,1]; DNG live neutral is applied only by source transform",
            "gamma": [1.0, 1.0],
            "auto_bright": False,
            "auto_scale": True,
            "adjust_maximum_thr": 0.0,
            "content_dependent_maximum_adjustment": False,
            "highlight_mode": "Clip; no highlight reconstruction",
            "normalization_policy": (
                "LibRaw black subtraction plus deterministic theoretical sensor-maximum scaling "
                "to 16-bit output; content-dependent maximum adjustment disabled; camera colour "
                "conversion disabled"
            ),
            "raw_sizes": _namedtuple_dict(sizes),
            "raw_pattern": raw_pattern,
            "color_desc": color_desc,
            "black_level_per_channel": [float(v) for v in raw.black_level_per_channel],
            "white_level": float(raw.white_level),
            "camera_white_level_per_channel": camera_white,
            "num_colors": int(raw.num_colors),
        }
    return rgb16, diag


def _channel_stats(values: np.ndarray) -> dict[str, Any]:
    arr = np.asarray(values, dtype=np.float64).reshape(-1, 3)
    percentiles = np.percentile(arr, [1.0, 50.0, 99.0], axis=0)
    return {
        "samples": int(arr.shape[0]),
        "mean": np.mean(arr, axis=0).tolist(),
        "min": np.min(arr, axis=0).tolist(),
        "p01": percentiles[0].tolist(),
        "p50": percentiles[1].tolist(),
        "p99": percentiles[2].tolist(),
        "max": np.max(arr, axis=0).tolist(),
        "fraction_below_0": float(np.mean(arr < 0.0)),
        "fraction_above_1": float(np.mean(arr > 1.0)),
    }


def pipeline_sample_diagnostics(
    rgb16: np.ndarray,
    source_transform: np.ndarray,
    tables: m11_reference.Tables,
    mode: str,
    toggles: dict[str, bool],
    max_samples: int = 120_000,
) -> dict[str, Any]:
    h, w = rgb16.shape[:2]
    stride = max(1, int(math.ceil(math.sqrt((h * w) / max_samples))))
    camera = rgb16[::stride, ::stride].astype(np.float64) / 65535.0
    xyz = dng_source.apply_camera_to_xyz(camera, source_transform)
    m11_in = m11_basis.apply_xyz_d50_to_m11_reference(xyz)
    out = m11_reference.render(m11_in, tables, mode, **toggles)
    return {
        "sample_stride": stride,
        "camera_rgb": _channel_stats(camera),
        "xyz_d50": _channel_stats(xyz),
        "m11_reference_input": _channel_stats(m11_in),
        "m11_output_code_values": _channel_stats(out),
    }


def render_chunks(
    rgb16: np.ndarray,
    source_transform: np.ndarray,
    tables: m11_reference.Tables,
    mode: str,
    toggles: dict[str, bool],
    chunk_rows: int,
) -> np.ndarray:
    h, w = rgb16.shape[:2]
    out8 = np.empty((h, w, 3), dtype=np.uint8)
    for y0 in range(0, h, chunk_rows):
        y1 = min(h, y0 + chunk_rows)
        camera = rgb16[y0:y1].astype(np.float64) / 65535.0
        xyz = dng_source.apply_camera_to_xyz(camera, source_transform)
        m11_in = m11_basis.apply_xyz_d50_to_m11_reference(xyz)
        rendered = m11_reference.render(m11_in, tables, mode, **toggles)
        out8[y0:y1] = np.clip(np.rint(rendered * 255.0), 0.0, 255.0).astype(np.uint8)
    return out8


def save_jpeg(path: Path, rgb8: np.ndarray, quality: int, profile_mode: str) -> dict[str, Any]:
    try:
        from PIL import Image, ImageCms
    except ImportError as exc:
        raise RuntimeError("Pillow is required to write the JPEG; install Pillow and retry") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.fromarray(rgb8, mode="RGB")
    kwargs: dict[str, Any] = {
        "format": "JPEG",
        "quality": quality,
        "subsampling": 0,
        "optimize": True,
    }
    icc_tagged = False
    if profile_mode == "srgb-tag":
        profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB"))
        kwargs["icc_profile"] = profile.tobytes()
        icc_tagged = True
    image.save(path, **kwargs)
    return {
        "format": "JPEG",
        "quality": quality,
        "subsampling": "4:4:4",
        "icc_srgb_tagged": icc_tagged,
        "encoding_assumption": (
            "frozen M11 reference-renderer code values are quantized directly to JPEG; "
            "no additional sRGB OETF or gamut transform is applied"
        ),
    }


def table_hashes(data_dir: Path) -> dict[str, str]:
    return {name: sha256_file(data_dir / name) for name in TABLE_FILENAMES}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Controlled Xiaomi DNG -> frozen M11 reference JPEG + diagnostics"
    )
    ap.add_argument("input", type=Path)
    ap.add_argument("--mode", choices=sorted(m11_reference.MODE_CONFIG), default="standard")
    ap.add_argument("--bridge", choices=["dng-native-v1"], default="dng-native-v1")
    ap.add_argument("--data-dir", type=Path, default=m11_reference.DEFAULT_DATA)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--diag", type=Path)
    ap.add_argument("--physical-camera-id", default=None)
    ap.add_argument("--decode-scale", choices=["auto", "full", "half"], default="auto")
    ap.add_argument("--chunk-rows", type=int, default=256)
    ap.add_argument("--jpeg-quality", type=int, default=97)
    ap.add_argument("--jpeg-profile", choices=["srgb-tag", "none"], default="srgb-tag")
    ap.add_argument("--strict-main-characterization", action="store_true")
    ap.add_argument("--disable-cc0", action="store_true")
    ap.add_argument("--disable-tone", action="store_true")
    ap.add_argument("--disable-cc1", action="store_true")
    ap.add_argument("--disable-gamma", action="store_true")
    ap.add_argument("--disable-chroma", action="store_true")
    args = ap.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input DNG not found: {args.input}")
    if args.chunk_rows <= 0:
        raise SystemExit("--chunk-rows must be > 0")
    if not 1 <= args.jpeg_quality <= 100:
        raise SystemExit("--jpeg-quality must be in 1..100")

    missing_tables = [name for name in TABLE_FILENAMES if not (args.data_dir / name).is_file()]
    if missing_tables:
        raise SystemExit(
            "forensic table directory is incomplete: "
            + ", ".join(missing_tables)
            + f"; validate it with renderer/reference/validate_forensics_data.py {args.data_dir}"
        )

    out = args.out or args.input.with_name(f"{args.input.stem}_M11_{args.mode}.jpg")
    diag_path = args.diag or out.with_suffix(".json")

    record = exiftool_record(args.input)
    meta = parse_dng_metadata(record)
    historical = compare_historical_main(meta)
    if args.strict_main_characterization and not historical.get(
        "historical_main_characterization_match", False
    ):
        raise SystemExit(
            "DNG static metadata does not match the recorded Xiaomi 15 Ultra main characterization"
        )

    source_result, source_diag = build_source_transform(meta)
    tables = m11_reference.load_tables(args.data_dir)
    rgb16, decode_diag = decode_camera_rgb(args.input, args.decode_scale)

    toggles = {
        "use_cc0": not args.disable_cc0,
        "use_tone": not args.disable_tone,
        "use_cc1": not args.disable_cc1,
        "use_gamma": not args.disable_gamma,
        "use_chroma": not args.disable_chroma,
        "clamp": True,
    }
    sample_diag = pipeline_sample_diagnostics(
        rgb16,
        source_result.camera_to_xyz_d50,
        tables,
        args.mode,
        toggles,
    )
    rgb8 = render_chunks(
        rgb16,
        source_result.camera_to_xyz_d50,
        tables,
        args.mode,
        toggles,
        args.chunk_rows,
    )
    jpeg_diag = save_jpeg(out, rgb8, args.jpeg_quality, args.jpeg_profile)

    diagnostics = {
        "schema": "m11camera.controlled_xiaomi_render.v1",
        "source_dng": {
            "path": str(args.input),
            "sha256": sha256_file(args.input),
            "physical_camera_id_user_label": args.physical_camera_id,
            "physical_camera_match_verified": False,
            "physical_camera_note": (
                "offline DNG metadata can support a main-characterization continuity check, "
                "but physical Camera2 result association is not independently proven here"
            ),
        },
        "dng_metadata": metadata_diagnostics(meta),
        "historical_main_characterization": historical,
        "decode": decode_diag,
        "source_bridge": source_diag,
        "m11_input_bridge": {
            "name": "m11-standard-a-reference-v1",
            "evidence_status": "strong inference, not firmware-proven",
            "xyz_d50_to_m11_reference_wb": m11_basis.xyz_d50_to_m11_a_reference_wb().tolist(),
            "xiaomi_specific_constants": False,
        },
        "m11_renderer": {
            "mode": args.mode,
            "stage_order": [
                "CC0",
                "luminance-dependent tone gain",
                "CC1",
                "RGB_to_Leica_YCC",
                "reconstructed_gamma_on_Y",
                "mode_chroma",
                "inverse_YCC",
                "clamp",
            ],
            "stage_toggles": toggles,
            "gamma_placement_status": "provisional frozen placement A; bounded A/B inconclusive",
            "table_directory": str(args.data_dir),
            "table_sha256": table_hashes(args.data_dir),
            "no_hdr": True,
            "no_local_tone_mapping": True,
            "no_highlight_reconstruction": True,
            "no_visual_lut_tuning": True,
            "project_side_lens_shading_stage": False,
        },
        "pipeline_samples": sample_diag,
        "output": {
            "path": str(out),
            "shape": list(rgb8.shape),
            "sha256": sha256_file(out),
            **jpeg_diag,
        },
    }

    diag_path.parent.mkdir(parents=True, exist_ok=True)
    diag_path.write_text(json.dumps(diagnostics, indent=2, default=_jsonable) + "\n")
    print(json.dumps({"jpeg": str(out), "diagnostics": str(diag_path)}, indent=2))


if __name__ == "__main__":
    main()
