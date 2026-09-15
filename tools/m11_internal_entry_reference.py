#!/usr/bin/env python3
"""Research-only Leica M11 internal working-space entry from XYZ D50.

Firmware closure shows live CC0 is the camera-space -> Leica internal transform.
For a source adapter that already ends in white-balanced XYZ D50, the correct
cross-camera entry is therefore the fixed firmware D50-PCS -> internal matrix K,
not a synthetic M11 sensor basis followed by another M11 camera calibration.

This module does not change RENDER1H.  It provides algebra/regression helpers for
validating a future deliberate integration change.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from renderer.m11_core import reference_basis


PCS_TO_INTERNAL = np.array(
    [
        [1.3460, -0.2556, -0.0511],
        [-0.5446, 1.5082, 0.0205],
        [0.0, 0.0, 1.2123],
    ],
    dtype=np.float64,
)

# Historical Category-3 candidate recorded before the dynamic-CC0 identity was
# understood.  Q9, denominator 512.
HISTORICAL_CATEGORY3_CC0 = np.array(
    [
        [495, -58, 63],
        [10, 601, -111],
        [49, -255, 705],
    ],
    dtype=np.float64,
) / 512.0


@dataclass(frozen=True)
class HistoricalEntryComparison:
    old_composite: np.ndarray
    best_scalar_to_k: float
    max_abs_residual_after_scalar: float
    rms_residual_after_scalar: float
    direct_k_relative_ev: float


@dataclass(frozen=True)
class SourceEntryComparison:
    old_camera_to_internal: np.ndarray
    direct_camera_to_internal: np.ndarray
    best_scalar_old_to_direct: float
    max_abs_residual_after_scalar: float
    rms_residual_after_scalar: float
    direct_relative_ev: float


def xyz_d50_to_internal(xyz) -> np.ndarray:
    values = np.asarray(xyz, dtype=np.float64)
    if values.shape[-1] != 3:
        raise ValueError("XYZ input must have three channels in the final dimension")
    return np.einsum("...j,ij->...i", values, PCS_TO_INTERNAL)


def _source_matrix(camera_to_xyz_d50) -> np.ndarray:
    matrix = np.asarray(camera_to_xyz_d50, dtype=np.float64)
    if matrix.shape != (3, 3):
        raise ValueError("camera_to_xyz_d50 must be 3x3")
    if not np.all(np.isfinite(matrix)):
        raise ValueError("camera_to_xyz_d50 contains non-finite values")
    return matrix


def camera_to_internal_matrix(camera_to_xyz_d50) -> np.ndarray:
    return PCS_TO_INTERNAL @ _source_matrix(camera_to_xyz_d50)


def historical_entry_comparison() -> HistoricalEntryComparison:
    old = HISTORICAL_CATEGORY3_CC0 @ reference_basis.xyz_d50_to_m11_a_reference_wb()
    k = PCS_TO_INTERNAL
    scalar = float(np.sum(old * k) / np.sum(k * k))
    residual = old - scalar * k
    # If old ~= scalar*K, direct K is brighter by -log2(scalar) EV.
    ev = float(-math.log2(scalar))
    return HistoricalEntryComparison(
        old_composite=old,
        best_scalar_to_k=scalar,
        max_abs_residual_after_scalar=float(np.max(np.abs(residual))),
        rms_residual_after_scalar=float(np.sqrt(np.mean(residual * residual))),
        direct_k_relative_ev=ev,
    )


def compare_source_entries(camera_to_xyz_d50) -> SourceEntryComparison:
    """Compare frozen old entry against direct-K for one white-balanced source transform."""
    source = _source_matrix(camera_to_xyz_d50)
    old_entry = HISTORICAL_CATEGORY3_CC0 @ reference_basis.xyz_d50_to_m11_a_reference_wb()
    old_camera_to_internal = old_entry @ source
    direct_camera_to_internal = PCS_TO_INTERNAL @ source
    scalar = float(
        np.sum(old_camera_to_internal * direct_camera_to_internal)
        / np.sum(direct_camera_to_internal * direct_camera_to_internal)
    )
    residual = old_camera_to_internal - scalar * direct_camera_to_internal
    return SourceEntryComparison(
        old_camera_to_internal=old_camera_to_internal,
        direct_camera_to_internal=direct_camera_to_internal,
        best_scalar_old_to_direct=scalar,
        max_abs_residual_after_scalar=float(np.max(np.abs(residual))),
        rms_residual_after_scalar=float(np.sqrt(np.mean(residual * residual))),
        direct_relative_ev=float(-math.log2(scalar)),
    )
