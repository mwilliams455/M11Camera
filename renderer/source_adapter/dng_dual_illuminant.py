#!/usr/bin/env python3
"""DNG/Camera2 dual-illuminant camera -> XYZ D50 reference math.

This module is deliberately target-agnostic. It converts a physical camera's
source characterization plus the live neutral point into a scene-referred
camera-to-XYZ-D50 transform. Leica M11 processing starts *after* this boundary.

The implementation is a clean Python reconstruction of the DNG math used by the
PhotonCamera Converter path inspected during the Xiaomi source-calibration work.
A critical convention is frozen here: DNG ColorMatrix1/2 are XYZ -> reference
camera matrices and are NOT ForwardMatrix-normalized.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

D50_XYZ = np.array([0.9642, 1.0, 0.8249], dtype=np.float64)

# DNG/Camera2 reference-illuminant enum values used by Android CameraMetadata.
STANDARD_ILLUMINANT_K = {
    1: 6504,   # Daylight
    2: 4230,   # Fluorescent
    3: 2856,   # Tungsten
    4: 5500,   # Flash
    9: 5500,   # Fine weather
    10: 6500,  # Cloudy weather
    11: 7500,  # Shade
    12: 6430,  # Daylight fluorescent
    13: 5000,  # Day white fluorescent
    14: 4230,  # Cool white fluorescent
    15: 3450,  # White fluorescent
    17: 2856,  # Standard Light A
    18: 4874,  # Standard Light B
    19: 6774,  # Standard Light C
    20: 5503,  # D55
    21: 6504,  # D65
    22: 7504,  # D75
    23: 5003,  # D50
    24: 3200,  # ISO studio tungsten
}


@dataclass(frozen=True)
class DualIlluminantResult:
    camera_to_xyz_d50: np.ndarray
    interpolation_factor: float
    reference_neutral: np.ndarray


def _matrix3(value, name: str) -> np.ndarray:
    out = np.asarray(value, dtype=np.float64)
    if out.size != 9:
        raise ValueError(f"{name} must contain 9 values")
    out = out.reshape(3, 3)
    if not np.all(np.isfinite(out)):
        raise ValueError(f"{name} contains non-finite values")
    return out


def _vector3(value, name: str) -> np.ndarray:
    out = np.asarray(value, dtype=np.float64).reshape(-1)
    if out.size != 3:
        raise ValueError(f"{name} must contain 3 values")
    if not np.all(np.isfinite(out)):
        raise ValueError(f"{name} contains non-finite values")
    return out


def lerp(a: np.ndarray, b: np.ndarray, factor: float) -> np.ndarray:
    """Photon/DNG convention: factor=0 selects first, factor=1 selects second."""
    return a * (1.0 - factor) + b * factor


def normalize_forward_matrix(forward_matrix) -> np.ndarray:
    """Normalize a DNG ForwardMatrix so camera white [1,1,1] maps to D50.

    This operation is *only* for ForwardMatrix. Applying it to ColorMatrix changes
    camera-channel relationships and is a source-calibration bug.
    """
    fm = _matrix3(forward_matrix, "forward_matrix")
    xyz = fm @ np.ones(3, dtype=np.float64)
    if np.any(~np.isfinite(xyz)) or np.any(np.abs(xyz) < 1e-12):
        raise ValueError("forward_matrix cannot be normalized: invalid white mapping")
    return np.diag(D50_XYZ / xyz) @ fm


def cie_xy_from_xyz(xyz) -> tuple[float, float]:
    xyz = _vector3(xyz, "xyz")
    total = float(np.sum(xyz))
    if total <= 1e-9:
        # Matches the defensive fallback in the inspected Photon Converter path.
        return 0.3127, 0.3290
    return float(xyz[0] / total), float(xyz[1] / total)


def mccamy_cct(x: float, y: float) -> float:
    """McCamy cubic CCT approximation used by the inspected Photon path."""
    denom = y - 0.1858
    if abs(denom) < 1e-9:
        denom = -1e-9 if denom < 0 else 1e-9
    n = (x - 0.332) / denom
    return float(-449.0 * n**3 + 3525.0 * n**2 - 6823.3 * n + 5520.33)


def find_dng_interpolation_factor(
    reference_illuminant1: int,
    reference_illuminant2: int,
    calibration_transform1,
    calibration_transform2,
    color_matrix1,
    color_matrix2,
    neutral_color_point,
    *,
    tolerance: float = 1e-4,
    max_iterations: int = 30,
) -> float:
    """Solve the dual-illuminant interpolation factor from a camera neutral.

    ColorMatrix inputs are consumed in their DNG XYZ->reference-camera convention
    exactly as supplied. They are never passed through ForwardMatrix normalization.
    """
    try:
        temperature1 = float(STANDARD_ILLUMINANT_K[int(reference_illuminant1)])
        temperature2 = float(STANDARD_ILLUMINANT_K[int(reference_illuminant2)])
    except KeyError as exc:
        raise ValueError(f"unsupported reference illuminant: {exc.args[0]}") from exc

    cal1 = _matrix3(calibration_transform1, "calibration_transform1")
    cal2 = _matrix3(calibration_transform2, "calibration_transform2")
    cm1 = _matrix3(color_matrix1, "color_matrix1")
    cm2 = _matrix3(color_matrix2, "color_matrix2")
    camera_neutral = _vector3(neutral_color_point, "neutral_color_point")

    xyz_to_camera1 = cal1 @ cm1
    xyz_to_camera2 = cal2 @ cm2

    lower = min(temperature1, temperature2)
    upper = max(temperature1, temperature2)
    factor = 0.5
    old_factor = factor

    for _ in range(max_iterations):
        xyz_to_camera = lerp(xyz_to_camera1, xyz_to_camera2, factor)
        try:
            camera_to_xyz = np.linalg.inv(xyz_to_camera)
        except np.linalg.LinAlgError as exc:
            raise ValueError("interpolated XYZ-to-camera matrix is singular") from exc

        neutral_xyz = camera_to_xyz @ camera_neutral
        x, y = cie_xy_from_xyz(neutral_xyz)
        temperature = mccamy_cct(x, y)

        if temperature <= lower:
            new_factor = 1.0
        elif temperature >= upper:
            new_factor = 0.0
        else:
            inv_t = 1.0 / temperature
            new_factor = (inv_t - 1.0 / upper) / (1.0 / lower - 1.0 / upper)

        # Preserve the first/second matrix ordering if reference #1 is the colder
        # endpoint rather than the warmer endpoint.
        if lower == temperature1:
            new_factor = 1.0 - new_factor

        # Photon damps the iterative update by averaging it with the prior guess.
        factor = 0.5 * (new_factor + old_factor)
        diff = abs(old_factor - factor)
        old_factor = factor
        if diff <= tolerance:
            break

    return float(factor)


def calculate_camera_to_xyz_d50_transform(
    forward_matrix1,
    forward_matrix2,
    calibration_transform1,
    calibration_transform2,
    neutral_color_point,
    interpolation_factor: float,
) -> tuple[np.ndarray, np.ndarray]:
    """Calculate the white-balanced camera -> XYZ D50 transform.

    ForwardMatrix1/2 should already be normalized with
    :func:`normalize_forward_matrix`.

    Returns `(camera_to_xyz_d50, reference_neutral)`.
    """
    fm1 = _matrix3(forward_matrix1, "forward_matrix1")
    fm2 = _matrix3(forward_matrix2, "forward_matrix2")
    cal1 = _matrix3(calibration_transform1, "calibration_transform1")
    cal2 = _matrix3(calibration_transform2, "calibration_transform2")
    camera_neutral = _vector3(neutral_color_point, "neutral_color_point")

    interpolated_cal = lerp(cal1, cal2, interpolation_factor)
    try:
        inverse_cal = np.linalg.inv(interpolated_cal)
    except np.linalg.LinAlgError as exc:
        raise ValueError("interpolated calibration transform is singular") from exc

    reference_neutral = inverse_cal @ camera_neutral
    reference_neutral = np.maximum(reference_neutral, 1e-6)
    max_neutral = float(np.max(reference_neutral))
    white_balance = np.diag(max_neutral / reference_neutral)

    interpolated_fm = lerp(fm1, fm2, interpolation_factor)
    camera_to_xyz_d50 = interpolated_fm @ white_balance @ inverse_cal
    return camera_to_xyz_d50, reference_neutral


def build_dual_illuminant_transform(
    reference_illuminant1: int,
    reference_illuminant2: int,
    calibration_transform1,
    calibration_transform2,
    color_matrix1,
    color_matrix2,
    forward_matrix1,
    forward_matrix2,
    neutral_color_point,
) -> DualIlluminantResult:
    """End-to-end source transform with the corrected matrix conventions."""
    factor = find_dng_interpolation_factor(
        reference_illuminant1,
        reference_illuminant2,
        calibration_transform1,
        calibration_transform2,
        color_matrix1,
        color_matrix2,
        neutral_color_point,
    )
    nfm1 = normalize_forward_matrix(forward_matrix1)
    nfm2 = normalize_forward_matrix(forward_matrix2)
    transform, reference_neutral = calculate_camera_to_xyz_d50_transform(
        nfm1,
        nfm2,
        calibration_transform1,
        calibration_transform2,
        neutral_color_point,
        factor,
    )
    return DualIlluminantResult(
        camera_to_xyz_d50=transform,
        interpolation_factor=factor,
        reference_neutral=reference_neutral,
    )


def apply_camera_to_xyz(camera_rgb, transform) -> np.ndarray:
    """Apply a row-major 3x3 camera->XYZ transform to RGB vectors/images."""
    rgb = np.asarray(camera_rgb, dtype=np.float64)
    m = _matrix3(transform, "transform")
    if rgb.shape[-1] != 3:
        raise ValueError("camera_rgb last dimension must be 3")
    return np.einsum("...j,ij->...i", rgb, m)
