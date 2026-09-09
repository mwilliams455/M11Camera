#!/usr/bin/env python3
"""Compare rawpy 0.27.1 Params values with the native LibRaw parameter audit."""
from __future__ import annotations

import argparse
from pathlib import Path

import rawpy


def parse_dump(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or not key:
            raise ValueError(f"malformed native audit line: {raw_line!r}")
        values[key] = value
    return values


def rawpy_expected(half_size: bool) -> dict[str, float | int]:
    p = rawpy.Params(
        demosaic_algorithm=rawpy.DemosaicAlgorithm.AHD,
        half_size=half_size,
        four_color_rgb=False,
        use_camera_wb=False,
        use_auto_wb=False,
        user_wb=[1.0, 1.0, 1.0, 1.0],
        output_color=rawpy.ColorSpace.raw,
        output_bps=16,
        no_auto_scale=False,
        no_auto_bright=True,
        adjust_maximum_thr=0.0,
        bright=1.0,
        highlight_mode=rawpy.HighlightMode.Clip,
        gamma=(1.0, 1.0),
    )
    return {
        "user_qual": p.user_qual,
        "half_size": int(p.half_size),
        "four_color_rgb": int(p.four_color_rgb),
        "dcb_iterations": p.dcb_iterations,
        "dcb_enhance_fl": int(p.dcb_enhance_fl),
        "fbdd_noiserd": p.fbdd_noiserd,
        "threshold": p.threshold,
        "med_passes": p.med_passes,
        "use_camera_wb": int(p.use_camera_wb),
        "use_auto_wb": int(p.use_auto_wb),
        "user_mul0": p.user_mul[0],
        "user_mul1": p.user_mul[1],
        "user_mul2": p.user_mul[2],
        "user_mul3": p.user_mul[3],
        "output_color": p.output_color,
        "output_bps": p.output_bps,
        "user_flip": p.user_flip,
        "user_black": p.user_black,
        "user_sat": p.user_sat,
        "no_auto_bright": int(p.no_auto_bright),
        "no_auto_scale": int(p.no_auto_scale),
        "auto_bright_thr": p.auto_bright_thr,
        "adjust_maximum_thr": p.adjust_maximum_thr,
        "bright": p.bright,
        "highlight": p.highlight,
        "exp_correc": p.exp_correc,
        "exp_shift": p.exp_shift,
        "exp_preser": p.exp_preser,
        "bad_pixels_null": int(p.bad_pixels is None),
        "gamm0": p.gamm[0],
        "gamm1": p.gamm[1],
        "aber0": p.aber[0],
        "aber2": p.aber[1],
    }


def compare(path: Path, half_size: bool) -> None:
    native = parse_dump(path)
    expected = rawpy_expected(half_size)
    missing = sorted(set(expected) - set(native))
    extra = sorted(set(native) - set(expected))
    if missing or extra:
        raise SystemExit(f"parameter key mismatch: missing={missing} extra={extra}")

    errors: list[str] = []
    for key, exp in expected.items():
        got_text = native[key]
        if isinstance(exp, int):
            try:
                got = int(got_text)
            except ValueError:
                errors.append(f"{key}: expected int {exp}, got {got_text!r}")
                continue
            if got != exp:
                errors.append(f"{key}: expected {exp}, got {got}")
        else:
            try:
                got = float(got_text)
            except ValueError:
                errors.append(f"{key}: expected float {exp!r}, got {got_text!r}")
                continue
            if abs(got - float(exp)) > 1e-7:
                errors.append(f"{key}: expected {float(exp):.17g}, got {got:.17g}")
    if errors:
        raise SystemExit("native/rawpy parameter mismatch:\n" + "\n".join(errors))
    print(f"rawpy_native_params_match=true half_size={str(half_size).lower()} fields={len(expected)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", type=Path)
    ap.add_argument("--half", action="store_true")
    args = ap.parse_args()
    compare(args.dump, args.half)


if __name__ == "__main__":
    main()
