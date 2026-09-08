#!/usr/bin/env python3
"""Provisional M11 XYZ-D50 -> Standard-A reference-camera basis bridge.

Evidence status: STRONG INFERENCE, not firmware-proven.

The matrix is derived from the genuine M11 DNG ColorMatrix1 (Standard Light A)
using Adobe-DNG-SDK-compatible no-ForwardMatrix white handling. It is not a
visual-fit matrix and contains no Xiaomi-specific constants.

The intended architecture is:
    Xiaomi source adapter -> linear XYZ D50
      -> this reference basis
      -> recorded M11 CC0 -> tone -> CC1 -> downstream firmware stages
"""
from __future__ import annotations

import numpy as np

M11_COLOR_MATRIX_A = np.array(
    [
        [0.57568359375, -0.13330078125, -0.01611328125],
        [-0.607421875, 1.5380859375, 0.435791015625],
        [-0.098388671875, 0.194580078125, 0.85546875],
    ],
    dtype=np.float64,
)

D50_XY = (0.34567, 0.35850)
STANDARD_A_XY = (0.44757, 0.40745)

BRADFORD = np.array(
    [
        [0.8951, 0.2664, -0.1614],
        [-0.7502, 1.7135, 0.0367],
        [0.0389, -0.0685, 1.0296],
    ],
    dtype=np.float64,
)
BRADFORD_INV = np.linalg.inv(BRADFORD)

# This value is retained as a regression target from the genuine-M11 12-DNG
# validation. The function below is the source of truth; callers should not use
# the literal independently.
RECORDED_REFERENCE_XYZ_D50_TO_M11_A_WB = np.array(
    [
        [1.31879337, -0.14831682, -0.14939568],
        [-0.51395518, 1.34347843, 0.18430135],
        [-0.27544169, 0.50342179, 0.92362240],
    ],
    dtype=np.float64,
)


def xy_to_xyz(xy: tuple[float, float]) -> np.ndarray:
    x, y = xy
    return np.array([x / y, 1.0, (1.0 - x - y) / y], dtype=np.float64)


def bradford_map(white1_xy, white2_xy) -> np.ndarray:
    """Adobe DNG MapWhiteMatrix direction: white1 -> white2."""
    w1 = BRADFORD @ xy_to_xyz(white1_xy)
    w2 = BRADFORD @ xy_to_xyz(white2_xy)
    ratios = np.clip(np.where(w1 > 0.0, w2 / w1, 10.0), 0.1, 10.0)
    return BRADFORD_INV @ np.diag(ratios) @ BRADFORD


def m11_a_camera_white() -> np.ndarray:
    """M11 Standard-A camera white normalized exactly as the DNG SDK path."""
    white = M11_COLOR_MATRIX_A @ xy_to_xyz(STANDARD_A_XY)
    white = white / np.max(white)
    return np.clip(white, 0.001, 1.0)


def m11_a_wb_camera_to_xyz_d50() -> np.ndarray:
    """White-balanced M11 Standard-A reference camera RGB -> XYZ D50 PCS."""
    pcs_to_camera = M11_COLOR_MATRIX_A @ bradford_map(D50_XY, STANDARD_A_XY)
    reach_saturation_scale = float(np.max(pcs_to_camera @ xy_to_xyz(D50_XY)))
    pcs_to_camera = pcs_to_camera / reach_saturation_scale
    camera_to_pcs = np.linalg.inv(pcs_to_camera)
    return camera_to_pcs @ np.diag(m11_a_camera_white())


def xyz_d50_to_m11_a_reference_wb() -> np.ndarray:
    """Linear XYZ D50 PCS -> M11 Standard-A reference white-balanced RGB."""
    return np.linalg.inv(m11_a_wb_camera_to_xyz_d50())


def apply_xyz_d50_to_m11_reference(xyz) -> np.ndarray:
    values = np.asarray(xyz, dtype=np.float64)
    if values.shape[-1] != 3:
        raise ValueError("XYZ input must have 3 channels in the final dimension")
    return np.einsum("...j,ij->...i", values, xyz_d50_to_m11_a_reference_wb())
