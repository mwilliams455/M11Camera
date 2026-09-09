#!/usr/bin/env python3
"""Generate deterministic stage-parity vectors from the frozen Python M11 renderer.

This is a cross-language validation oracle only. It deliberately uses synthetic
numeric tables so parity can be tested without bundling proprietary firmware or
requiring the canonical extraction. The stage ordering and mathematics come from
renderer/reference/leica_m11_reference_renderer.py itself.

The generated binary records expected Python values for:
  input -> CC0 -> tone scalar -> CC1 -> YCC/gamma/chroma -> output
across creative modes, stage toggles, negative values, highlights and clamping.
"""
from __future__ import annotations

import argparse
import base64
import struct
from pathlib import Path

import numpy as np

from renderer.reference import leica_m11_reference_renderer as ref

MAGIC = b"M11PAR1A"
VERSION = 1

MODE_IDS = {"natural": 0, "standard": 1, "vivid": 2}

POINTS = (
    (0.02, 0.04, 0.08),
    (0.18, 0.18, 0.18),
    (0.65, 0.25, 0.12),
    (0.10, 0.70, 0.30),
    (1.20, 0.90, 0.40),
    (-0.05, 0.20, 0.60),
    (0.95, 0.05, 0.75),
)

# cc0, tone, cc1, gamma, chroma, clamp
CONFIGS = (
    ("full", (True, True, True, True, True, True)),
    ("full_unclamped", (True, True, True, True, True, False)),
    ("tone_only", (False, True, False, False, False, False)),
    ("cc0_cc1", (True, False, True, False, False, False)),
    ("gamma_only", (False, False, False, True, False, False)),
    ("chroma_only", (False, False, False, False, True, False)),
    ("gamma_chroma", (False, False, False, True, True, False)),
)


def synthetic_tables() -> ref.Tables:
    cc0 = np.array(
        [[495, -58, 63], [10, 601, -111], [49, -255, 705]], dtype=np.float64
    ) / 512.0
    cc1 = np.array(
        [[1041, -372, -157], [-117, 630, -1], [-4, -78, 595]], dtype=np.float64
    ) / 512.0

    tone_x = np.linspace(0.0, 1.0, 17, dtype=np.float64)
    tone_curves = {}
    for contrast in range(-3, 4):
        exponent = 1.0 - 0.055 * contrast
        scale = 1.0 + 0.025 * contrast
        tone_curves[contrast] = np.clip(np.power(tone_x, exponent) * scale, 0.0, 1.25)

    gamma_x = np.linspace(0.0, 1.0, 33, dtype=np.float64)
    gamma_y = np.power(gamma_x, 1.0 / 2.15)
    return ref.Tables(cc0, cc1, tone_x, tone_curves, gamma_x, gamma_y)


def stage_trace(rgb: tuple[float, float, float], tables: ref.Tables, mode: str,
                use_cc0: bool, use_tone: bool, use_cc1: bool,
                use_gamma: bool, use_chroma: bool, clamp: bool) -> dict:
    cfg = ref.MODE_CONFIG[mode]
    out = np.asarray(rgb, dtype=np.float64).copy()

    if use_cc0:
        out = ref.apply_matrix(out, tables.cc0)
    after_cc0 = out.copy()

    tone_y = float(np.einsum("j,j->", out, ref.TONE_Y))
    tone_y2 = tone_y
    tone_scale = 1.0
    if use_tone:
        lookup = float(np.clip(tone_y, 0.0, 1.0))
        tone_y2 = float(np.interp(lookup, tables.tone_x, tables.tone_curves[cfg["contrast"]]))
        if tone_y > 1e-10:
            tone_scale = tone_y2 / max(tone_y, 1e-10)
            out *= tone_scale
    after_tone = out.copy()

    if use_cc1:
        out = ref.apply_matrix(out, tables.cc1)
    after_cc1 = out.copy()

    has_ycc = use_gamma or use_chroma
    ycc_before = np.full(3, np.nan, dtype=np.float64)
    ycc_after = np.full(3, np.nan, dtype=np.float64)
    if has_ycc:
        ycc = ref.apply_matrix(out, ref.YCC_M)
        ycc_before = ycc.copy()
        if use_gamma:
            y = float(np.clip(ycc[0], 0.0, 1.0))
            ycc[0] = np.interp(y, tables.gamma_x, tables.gamma_y)
        if use_chroma:
            ycc[1] *= cfg["chroma"]
            ycc[2] *= cfg["chroma"]
        ycc_after = ycc.copy()
        out = ref.ycc_to_rgb(ycc)

    if clamp:
        out = np.clip(out, 0.0, 1.0)

    expected_final = ref.render(
        np.asarray(rgb, dtype=np.float64), tables, mode,
        use_cc0=use_cc0, use_tone=use_tone, use_cc1=use_cc1,
        use_gamma=use_gamma, use_chroma=use_chroma, clamp=clamp,
    )
    if not np.allclose(out, expected_final, rtol=0.0, atol=1e-14):
        raise AssertionError(f"stage oracle diverged from Python render() for {mode} {rgb}")

    return {
        "after_cc0": after_cc0,
        "tone_y": tone_y,
        "tone_y2": tone_y2,
        "tone_scale": tone_scale,
        "after_tone": after_tone,
        "after_cc1": after_cc1,
        "has_ycc": has_ycc,
        "ycc_before": ycc_before,
        "ycc_after": ycc_after,
        "output": out,
    }


def generate() -> bytes:
    tables = synthetic_tables()
    cases = [
        (mode, point, flags)
        for mode in ("natural", "standard", "vivid")
        for point in POINTS
        for _name, flags in CONFIGS
    ]

    out = bytearray(MAGIC)
    out += struct.pack(">II", VERSION, len(cases))
    for mode, point, flags in cases:
        trace = stage_trace(point, tables, mode, *flags)
        flag_bits = sum((1 << i) for i, enabled in enumerate(flags) if enabled)
        out += struct.pack(">BBH", MODE_IDS[mode], flag_bits, 0)
        out += struct.pack(">3d", *point)
        out += struct.pack(">3d", *trace["after_cc0"])
        out += struct.pack(">3d", trace["tone_y"], trace["tone_y2"], trace["tone_scale"])
        out += struct.pack(">3d", *trace["after_tone"])
        out += struct.pack(">3d", *trace["after_cc1"])
        out += struct.pack(">I", 1 if trace["has_ycc"] else 0)
        out += struct.pack(">3d", *trace["ycc_before"])
        out += struct.pack(">3d", *trace["ycc_after"])
        out += struct.pack(">3d", *trace["output"])
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True, help="base64 parity fixture path")
    args = ap.parse_args()
    raw = generate()
    encoded = base64.encodebytes(raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(encoded)
    print(f"cases={3 * len(POINTS) * len(CONFIGS)} raw_bytes={len(raw)} base64_bytes={len(encoded)} out={args.out}")


if __name__ == "__main__":
    main()
