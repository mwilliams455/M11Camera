#!/usr/bin/env python3
"""Build a firmware-derived Leica M11 reference renderer and .cube LUTs.

This is a forensic/reference implementation based on decoded Leica M11-P 2.6.1
firmware tables. It is NOT yet a Xiaomi-specific DCP/LUT profile.

Working model (base ISO):
    linear RGB
      -> CC0 (Q9 / 512)
      -> luminance-dependent Leica tone gain (1024 points, Q12)
      -> CC1 (Q9 / 512)
      -> RGB -> YCbCr-like Leica/BT.601 integer matrix
      -> Leica gamma (4096-step reconstructed table; applied to Y)
      -> mode-dependent symmetric chroma scaling
      -> inverse YCbCr -> RGB
      -> output clamp

Film-mode defaults recovered from firmware:
    Natural:  contrast -1, saturation -1 => 100% chroma
    Standard: contrast  0, saturation  0 => 115% chroma
    Vivid:    contrast +1, saturation +1 => 130% chroma

The exact placement of the gamma table is still a reference-model assumption; all
stages can be toggled for validation against Leica JPEG/DNG pairs later.
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
DEFAULT_DATA = HERE / "M11P_color_forensics_v0.3"

MODE_CONFIG = {
    "natural": {"contrast": -1, "chroma": 1.00},
    "standard": {"contrast": 0, "chroma": 1.15},
    "vivid": {"contrast": +1, "chroma": 1.30},
}

# Leica integer YC matrix from category 24. This maps RGB to a Y/Cb/Cr-like
# zero-centered chroma representation. Divide by 256.
YCC_M = np.array(
    [
        [77, 150, 29],
        [-43, -85, 128],
        [128, -107, -21],
    ],
    dtype=np.float64,
) / 256.0
YCC_INV = np.linalg.inv(YCC_M)

# Tone-control luma weights from the tone control structure (sum = 255).
TONE_Y = np.array([77, 149, 29], dtype=np.float64) / 255.0


@dataclass
class Tables:
    cc0: np.ndarray
    cc1: np.ndarray
    tone_x: np.ndarray
    tone_curves: dict[int, np.ndarray]
    gamma_x: np.ndarray
    gamma_y: np.ndarray


def _load_json(path: Path):
    return json.loads(path.read_text())


def load_tables(data_dir: Path) -> Tables:
    cc0j = _load_json(data_dir / "category3_CC0_candidate.json")
    cc1j = _load_json(data_dir / "category13_CC1_candidate.json")

    # Category 3/13 begin with a shift/control word followed by 9 signed matrix coeffs.
    cc0_raw = np.asarray(cc0j["signed_int16"][1:10], dtype=np.float64).reshape(3, 3)
    cc1_raw = np.asarray(cc1j["signed_int16"][1:10], dtype=np.float64).reshape(3, 3)
    cc0 = cc0_raw / 512.0
    cc1 = cc1_raw / 512.0

    tone_path = data_dir / "tone_q12_reconstructed_curves.csv"
    with tone_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    tone_x = np.array([float(r["input_norm"]) for r in rows], dtype=np.float64)
    tone_curves = {}
    for c in range(-3, 4):
        key = f"contrast_{c}_output_norm_q12_model"
        tone_curves[c] = np.array([float(r[key]) for r in rows], dtype=np.float64)

    gamma_path = data_dir / "gamma_4096_high_nibble_first.csv"
    with gamma_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    gamma_x = np.array([float(r["input_norm"]) for r in rows], dtype=np.float64)
    gamma_y = np.array([float(r["output_norm"]) for r in rows], dtype=np.float64)

    return Tables(
        cc0=cc0,
        cc1=cc1,
        tone_x=tone_x,
        tone_curves=tone_curves,
        gamma_x=gamma_x,
        gamma_y=gamma_y,
    )


def apply_matrix(rgb: np.ndarray, m: np.ndarray) -> np.ndarray:
    return np.einsum("...j,ij->...i", rgb, m)


def apply_tone_luma(rgb: np.ndarray, tables: Tables, contrast: int) -> np.ndarray:
    """Apply Leica's modeled 1024-point Q12 tone-gain curve to luminance.

    Chroma is retained by scaling RGB by Yout/Yin. This is the most faithful
    portable model given the current firmware evidence; dedicated ISP behavior
    will be validated later against real Leica JPEG/DNG pairs.
    """
    y = np.einsum("...j,j->...", rgb, TONE_Y)
    y_lookup = np.clip(y, 0.0, 1.0)
    y2 = np.interp(y_lookup, tables.tone_x, tables.tone_curves[contrast])
    # For values above nominal white keep the ratio at the last valid point.
    # Negative scene values remain unmodified until later gamut handling.
    eps = 1e-10
    ratio = np.where(y > eps, y2 / np.maximum(y, eps), 1.0)
    return rgb * ratio[..., None]


def apply_gamma_ycc(rgb: np.ndarray, tables: Tables) -> np.ndarray:
    """Convert to Leica integer Y/Cb/Cr basis and apply reconstructed gamma to Y."""
    ycc = apply_matrix(rgb, YCC_M)
    y = ycc[..., 0]
    y_lookup = np.clip(y, 0.0, 1.0)
    ycc[..., 0] = np.interp(y_lookup, tables.gamma_x, tables.gamma_y)
    return ycc


def ycc_to_rgb(ycc: np.ndarray) -> np.ndarray:
    return apply_matrix(ycc, YCC_INV)


def render(
    rgb: np.ndarray,
    tables: Tables,
    mode: str,
    use_cc0: bool = True,
    use_tone: bool = True,
    use_cc1: bool = True,
    use_gamma: bool = True,
    use_chroma: bool = True,
    clamp: bool = True,
) -> np.ndarray:
    cfg = MODE_CONFIG[mode]
    out = np.asarray(rgb, dtype=np.float64).copy()

    if use_cc0:
        out = apply_matrix(out, tables.cc0)
    if use_tone:
        out = apply_tone_luma(out, tables, cfg["contrast"])
    if use_cc1:
        out = apply_matrix(out, tables.cc1)

    # YCC conversion is needed for gamma and/or creative chroma.
    if use_gamma or use_chroma:
        ycc = apply_matrix(out, YCC_M)
        if use_gamma:
            y = np.clip(ycc[..., 0], 0.0, 1.0)
            ycc[..., 0] = np.interp(y, tables.gamma_x, tables.gamma_y)
        if use_chroma:
            ycc[..., 1] *= cfg["chroma"]
            ycc[..., 2] *= cfg["chroma"]
        out = ycc_to_rgb(ycc)

    if clamp:
        out = np.clip(out, 0.0, 1.0)
    return out


def srgb_decode(x):
    x = np.asarray(x, dtype=np.float64)
    return np.where(x <= 0.04045, x / 12.92, ((x + 0.055) / 1.055) ** 2.4)


def srgb_encode(x):
    x = np.asarray(x, dtype=np.float64)
    x = np.clip(x, 0.0, None)
    return np.where(x <= 0.0031308, 12.92 * x, 1.055 * np.power(x, 1 / 2.4) - 0.055)


def cube_points(size: int):
    # .cube convention: red changes fastest, then green, then blue.
    vals = np.linspace(0.0, 1.0, size)
    for b in vals:
        for g in vals:
            for r in vals:
                yield np.array([r, g, b], dtype=np.float64)


def write_cube(
    path: Path,
    tables: Tables,
    mode: str,
    size: int,
    input_encoding: str = "linear",
    variant: str = "full",
):
    toggles = {
        "full": dict(use_cc0=True, use_tone=True, use_cc1=True, use_gamma=True, use_chroma=True),
        "creative": dict(use_cc0=False, use_tone=True, use_cc1=False, use_gamma=False, use_chroma=True),
        "color_only": dict(use_cc0=True, use_tone=False, use_cc1=True, use_gamma=False, use_chroma=True),
    }[variant]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="\n") as f:
        f.write(f'TITLE "Leica M11-P 2.6.1 {mode.title()} reference / {variant} / {input_encoding}"\n')
        f.write(f"LUT_3D_SIZE {size}\n")
        f.write("DOMAIN_MIN 0.0 0.0 0.0\n")
        f.write("DOMAIN_MAX 1.0 1.0 1.0\n")
        f.write("# Firmware-derived forensic reference, not yet Xiaomi-sensor calibrated.\n")
        f.write("# CC0/CC1 and gamma placement remain validation targets against real Leica JPEG/DNG pairs.\n")
        batch = []
        for p in cube_points(size):
            x = srgb_decode(p) if input_encoding == "srgb" else p
            batch.append(x)
            if len(batch) >= 8192:
                arr = np.vstack(batch)
                y = render(arr, tables, mode, **toggles)
                if input_encoding == "srgb" and variant != "full":
                    # For creative/post-render tests keep I/O in same sRGB code-value space.
                    y = srgb_encode(y)
                for row in y:
                    f.write(f"{row[0]:.9f} {row[1]:.9f} {row[2]:.9f}\n")
                batch = []
        if batch:
            arr = np.vstack(batch)
            y = render(arr, tables, mode, **toggles)
            if input_encoding == "srgb" and variant != "full":
                y = srgb_encode(y)
            for row in y:
                f.write(f"{row[0]:.9f} {row[1]:.9f} {row[2]:.9f}\n")


def hsv_from_rgb(rgb):
    # vectorized colorsys-like HSV for diagnostics (expects [0,1]).
    rgb = np.asarray(rgb)
    mx = rgb.max(axis=-1)
    mn = rgb.min(axis=-1)
    d = mx - mn
    h = np.zeros_like(mx)
    mask = d > 1e-12
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    mr = mask & (mx == r)
    mg = mask & (mx == g)
    mb = mask & (mx == b)
    h[mr] = ((g[mr] - b[mr]) / d[mr]) % 6
    h[mg] = (b[mg] - r[mg]) / d[mg] + 2
    h[mb] = (r[mb] - g[mb]) / d[mb] + 4
    h = (h / 6.0) % 1.0
    s = np.where(mx > 1e-12, d / np.maximum(mx, 1e-12), 0.0)
    return np.stack([h, s, mx], axis=-1)


def rgb_from_hsv(hsv):
    h, s, v = np.moveaxis(np.asarray(hsv), -1, 0)
    h6 = (h % 1.0) * 6
    i = np.floor(h6).astype(int)
    f = h6 - i
    p = v * (1 - s)
    q = v * (1 - s * f)
    t = v * (1 - s * (1 - f))
    out = np.empty(hsv.shape)
    cases = [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)]
    for k, (rr, gg, bb) in enumerate(cases):
        m = (i % 6) == k
        out[..., 0][m] = rr[m]
        out[..., 1][m] = gg[m]
        out[..., 2][m] = bb[m]
    return out


def write_diagnostics(path: Path, tables: Tables):
    rows = []
    hues = np.arange(0, 360, 10, dtype=float)
    for sat in (0.25, 0.5, 0.75, 1.0):
        hsv = np.stack([hues / 360.0, np.full_like(hues, sat), np.full_like(hues, 0.65)], axis=-1)
        rgb = rgb_from_hsv(hsv)
        for mode in MODE_CONFIG:
            out = render(rgb, tables, mode)
            oh = hsv_from_rgb(out)
            for j, h in enumerate(hues):
                dh = ((oh[j, 0] * 360 - h + 180) % 360) - 180
                rows.append(
                    {
                        "mode": mode,
                        "input_hue_deg": h,
                        "input_sat": sat,
                        "input_value": 0.65,
                        "out_r": out[j, 0],
                        "out_g": out[j, 1],
                        "out_b": out[j, 2],
                        "out_hue_deg": oh[j, 0] * 360,
                        "hue_shift_deg": dh,
                        "out_sat": oh[j, 1],
                        "out_value": oh[j, 2],
                    }
                )
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_manifest(path: Path, tables: Tables):
    obj = {
        "model": "Leica M11-P firmware-derived reference renderer v0.1",
        "source_firmware": "LEICA_M11-P_2.6.1.FW",
        "input_assumption": "normalized scene-linear M11 working RGB; Xiaomi bridge not yet applied",
        "pipeline": [
            "CC0 /512",
            "tone 1024-point Q12 luminance gain",
            "CC1 /512",
            "RGB->YCC",
            "gamma 4096-step on Y",
            "symmetric chroma scale",
            "YCC->RGB",
            "clip",
        ],
        "modes": MODE_CONFIG,
        "matrices": {
            "CC0": tables.cc0.tolist(),
            "CC1_low_iso": tables.cc1.tolist(),
            "YCC": YCC_M.tolist(),
            "tone_luma_weights": TONE_Y.tolist(),
        },
        "known_limitations": [
            "CC0/CC1 are M11 internal transforms and are not directly portable to Xiaomi sensor RGB.",
            "Gamma placement/application to Y is a reference-model assumption pending Leica JPEG/DNG validation.",
            "Leica LTM, AWB, noise-dependent chroma protection, and sharpening are deliberately excluded.",
            "Output gamut handling is simple clipping for forensic reproducibility.",
        ],
    }
    path.write_text(json.dumps(obj, indent=2) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--out-dir", type=Path, default=HERE / "M11P_reference_renderer_v0.1")
    ap.add_argument("--sizes", type=int, nargs="*", default=[33, 65])
    ap.add_argument("--modes", nargs="*", choices=list(MODE_CONFIG), default=list(MODE_CONFIG))
    args = ap.parse_args()

    t = load_tables(args.data_dir)
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    # Main forensic full-reference cubes: linear input -> Leica-mode display-like output.
    for size in args.sizes:
        for mode in args.modes:
            write_cube(
                out / f"Leica_M11P_{mode.title()}_FULL_REFERENCE_LINEAR_{size}.cube",
                t,
                mode,
                size,
                "linear",
                "full",
            )

    # Smaller diagnostic/post-DCP candidate variants, intentionally separate.
    for mode in args.modes:
        write_cube(
            out / f"Leica_M11P_{mode.title()}_CREATIVE_ONLY_sRGB_33.cube",
            t,
            mode,
            33,
            "srgb",
            "creative",
        )
        write_cube(
            out / f"Leica_M11P_{mode.title()}_COLOR_ONLY_LINEAR_33.cube",
            t,
            mode,
            33,
            "linear",
            "color_only",
        )

    write_diagnostics(out / "hue_saturation_diagnostics.csv", t)
    write_manifest(out / "reference_model.json", t)
    print(out)


if __name__ == "__main__":
    main()
