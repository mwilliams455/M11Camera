#!/usr/bin/env python3
"""Firmware-faithful reference implementation of Leica M11-P 2.6.1 ColorSpec CC0.

This module is research/reference code.  It reproduces the closed live path from
frame AWB gains through dual-illuminant ColorSpec, Bradford white adaptation,
the D50 PCS -> internal ROMM-like basis transform and the 44-byte R2Y CC0
record.  It does not alter the photographic renderer.
"""
from __future__ import annotations

import math
import struct
from typing import Iterable, Sequence

Matrix3 = tuple[float, float, float, float, float, float, float, float, float]
Vector3 = tuple[float, float, float]
XY = tuple[float, float]

COEFF_MIN = -2048
COEFF_MAX = 2047
D50_XY: XY = (0.3457, 0.3585)
NEUTRAL_TO_XY_EPSILON = 1.0e-7
NEUTRAL_TO_XY_MAX_PASSES = 15

# Firmware runtime 0x422247D0: D50 PCS/XYZ -> Leica internal ROMM/ProPhoto-like RGB.
PCS_TO_INTERNAL: Matrix3 = (
    1.3460, -0.2556, -0.0511,
    -0.5446, 1.5082, 0.0205,
    0.0, 0.0, 1.2123,
)

# Firmware runtime 0x42224598 / 0x422245E0.
BRADFORD: Matrix3 = (
    0.8951, 0.2664, -0.1614,
    -0.7502, 1.7135, 0.0367,
    0.0389, -0.0685, 1.0296,
)
BRADFORD_INV: Matrix3 = (
    0.9869929, -0.1470543, 0.1599627,
    0.4323053, 0.5183603, 0.0492912,
    -0.0085287, 0.0400428, 0.9684867,
)

# R2Y_CC0_CM.bin records 1 and 2.  Both are Q12 matrices.
CM1_RAW = (2358, -546, -66, -2488, 6300, 1785, -403, 797, 3504)
CM2_RAW = (1700, -326, -200, -2354, 5409, 974, -612, 976, 2276)
CM1_SHIFT = 12
CM2_SHIFT = 12
CM1_TEMPERATURE = 2850.0
CM2_TEMPERATURE = 6807.0
CM1: Matrix3 = tuple(v / float(1 << CM1_SHIFT) for v in CM1_RAW)  # type: ignore[assignment]
CM2: Matrix3 = tuple(v / float(1 << CM2_SHIFT) for v in CM2_RAW)  # type: ignore[assignment]

# Exact 31 x 4 doubles from M11-P 2.6.1 runtime 0x42224B38.
# Important firmware difference: r=325 stores u=0.24792.  Adobe's published
# DNG SDK table commonly stores 0.24702 at that row; parity must use Leica's
# firmware value below.
TEMP_TABLE: tuple[tuple[float, float, float, float], ...] = (
    (0, 0.18006, 0.26352, -0.24341),
    (10, 0.18066, 0.26589, -0.25479),
    (20, 0.18133, 0.26846, -0.26876),
    (30, 0.18208, 0.27119, -0.28539),
    (40, 0.18293, 0.27407, -0.30470),
    (50, 0.18388, 0.27709, -0.32675),
    (60, 0.18494, 0.28021, -0.35156),
    (70, 0.18611, 0.28342, -0.37915),
    (80, 0.18740, 0.28668, -0.40955),
    (90, 0.18880, 0.28997, -0.44278),
    (100, 0.19032, 0.29326, -0.47888),
    (125, 0.19462, 0.30141, -0.58204),
    (150, 0.19962, 0.30921, -0.70471),
    (175, 0.20525, 0.31647, -0.84901),
    (200, 0.21142, 0.32312, -1.0182),
    (225, 0.21807, 0.32909, -1.2168),
    (250, 0.22511, 0.33439, -1.4512),
    (275, 0.23247, 0.33904, -1.7298),
    (300, 0.24010, 0.34308, -2.0637),
    (325, 0.24792, 0.34655, -2.4681),
    (350, 0.25591, 0.34951, -2.9641),
    (375, 0.26400, 0.35200, -3.5814),
    (400, 0.27218, 0.35407, -4.3633),
    (425, 0.28039, 0.35577, -5.3762),
    (450, 0.28863, 0.35714, -6.7262),
    (475, 0.29685, 0.35823, -8.5955),
    (500, 0.30505, 0.35907, -11.324),
    (525, 0.31320, 0.35968, -15.628),
    (550, 0.32129, 0.36011, -23.325),
    (575, 0.32931, 0.36038, -40.770),
    (600, 0.33724, 0.36051, -116.45),
)


def _matrix9(values: Iterable[float]) -> Matrix3:
    v = tuple(float(x) for x in values)
    if len(v) != 9:
        raise ValueError("expected 9 matrix coefficients")
    return v  # type: ignore[return-value]


def _vector3(values: Iterable[float]) -> Vector3:
    v = tuple(float(x) for x in values)
    if len(v) != 3:
        raise ValueError("expected 3 vector values")
    return v  # type: ignore[return-value]


def matmul3x3(a: Sequence[float], b: Sequence[float]) -> Matrix3:
    """Row-major 3x3 multiply matching firmware helper 0x016EE62C."""
    aa = _matrix9(a)
    bb = _matrix9(b)
    out = []
    for r in range(3):
        for c in range(3):
            out.append(
                aa[r * 3 + 0] * bb[0 * 3 + c]
                + aa[r * 3 + 1] * bb[1 * 3 + c]
                + aa[r * 3 + 2] * bb[2 * 3 + c]
            )
    return _matrix9(out)


def matvec3(a: Sequence[float], v: Sequence[float]) -> Vector3:
    aa = _matrix9(a)
    vv = _vector3(v)
    return (
        aa[0] * vv[0] + aa[1] * vv[1] + aa[2] * vv[2],
        aa[3] * vv[0] + aa[4] * vv[1] + aa[5] * vv[2],
        aa[6] * vv[0] + aa[7] * vv[1] + aa[8] * vv[2],
    )


def diag3(values: Sequence[float]) -> Matrix3:
    x, y, z = _vector3(values)
    return (x, 0.0, 0.0, 0.0, y, 0.0, 0.0, 0.0, z)


def inverse3x3(matrix: Sequence[float]) -> Matrix3:
    """Adjugate/determinant inverse matching 0x016EE294 + 0x016EE5B4."""
    a = _matrix9(matrix)
    a00, a01, a02, a10, a11, a12, a20, a21, a22 = a
    c00 = a11 * a22 - a12 * a21
    c01 = a02 * a21 - a01 * a22
    c02 = a01 * a12 - a02 * a11
    c10 = a12 * a20 - a10 * a22
    c11 = a00 * a22 - a02 * a20
    c12 = a02 * a10 - a00 * a12
    c20 = a10 * a21 - a11 * a20
    c21 = a01 * a20 - a00 * a21
    c22 = a00 * a11 - a01 * a10
    determinant = a00 * c00 + a01 * c10 + a02 * c20
    if determinant == 0.0 or not math.isfinite(determinant):
        raise ValueError("singular/non-finite 3x3 matrix")
    scale = 1.0 / determinant
    return tuple(x * scale for x in (c00, c01, c02, c10, c11, c12, c20, c21, c22))  # type: ignore[return-value]


def xy_to_xyz(xy: Sequence[float]) -> Vector3:
    if len(xy) != 2:
        raise ValueError("expected xy pair")
    x, y = float(xy[0]), float(xy[1])
    if y <= 0.0:
        return (0.0, 0.0, 0.0)
    return (x / y, 1.0, (1.0 - x - y) / y)


def xyz_to_xy(xyz: Sequence[float]) -> XY:
    x, y, z = _vector3(xyz)
    total = x + y + z
    # Firmware helper 0x016F1BE0 uses total > 1.0, not merely total > 0.
    if total > 1.0:
        return (x / total, y / total)
    return D50_XY


def xy_to_temperature_tint(xy: Sequence[float]) -> tuple[float, float]:
    """Firmware 0x016EFD34: Robertson/Wyszecki-Stiles xy -> CCT/tint."""
    if len(xy) != 2:
        raise ValueError("expected xy pair")
    x, y = float(xy[0]), float(xy[1])
    denominator = 1.5 - x + 6.0 * y
    if denominator == 0.0:
        raise ValueError("invalid xy denominator")
    u = 2.0 * x / denominator
    v = 3.0 * y / denominator

    last_dt = 0.0
    last_du = 0.0
    last_dv = 0.0

    for index in range(1, 31):
        r_i, u_i, v_i, t_i = TEMP_TABLE[index]
        du = 1.0
        dv = t_i
        length = math.sqrt(1.0 + dv * dv)
        du /= length
        dv /= length

        uu = u - u_i
        vv = v - v_i
        dt = -uu * dv + vv * du

        if dt <= 0.0 or index == 30:
            if dt > 0.0:
                dt = 0.0
            dt = -dt
            f = 0.0 if index == 1 else dt / (last_dt + dt)
            r_0, u_0, v_0, _t_0 = TEMP_TABLE[index - 1]
            temperature = 1.0e6 / (r_0 * f + r_i * (1.0 - f))

            uu = u - (u_0 * f + u_i * (1.0 - f))
            vv = v - (v_0 * f + v_i * (1.0 - f))
            du = du * (1.0 - f) + last_du * f
            dv = dv * (1.0 - f) + last_dv * f
            length = math.sqrt(du * du + dv * dv)
            du /= length
            dv /= length
            tint = (uu * du + vv * dv) * -3000.0
            return (temperature, tint)

        last_dt = dt
        last_du = du
        last_dv = dv

    raise AssertionError("temperature search did not terminate")


def interpolate_color_matrix(temperature: float) -> Matrix3:
    """Firmware 0x016ED368 reciprocal-temperature interpolation of CM1/CM2."""
    t = float(temperature)
    if t <= CM1_TEMPERATURE:
        return CM1
    if t >= CM2_TEMPERATURE:
        return CM2
    inv_t = 1.0 / t
    g = (inv_t - 1.0 / CM2_TEMPERATURE) / (
        1.0 / CM1_TEMPERATURE - 1.0 / CM2_TEMPERATURE
    )
    return tuple(g * a + (1.0 - g) * b for a, b in zip(CM1, CM2))  # type: ignore[return-value]


def neutral_to_xy(neutral: Sequence[float]) -> tuple[XY, float, float, Matrix3]:
    """Firmware 0x016ED060: 15-pass D50-seeded NeutralToXY solver."""
    n = _vector3(neutral)
    last = D50_XY

    for pass_index in range(NEUTRAL_TO_XY_MAX_PASSES):
        temperature, _tint = xy_to_temperature_tint(last)
        color_matrix = interpolate_color_matrix(temperature)
        next_xy = xyz_to_xy(matvec3(inverse3x3(color_matrix), n))

        if (
            abs(next_xy[0] - last[0]) + abs(next_xy[1] - last[1])
            < NEUTRAL_TO_XY_EPSILON
        ):
            last = next_xy
            break

        if pass_index == NEUTRAL_TO_XY_MAX_PASSES - 1:
            # Firmware anti-oscillation fallback: average the final two estimates.
            next_xy = (
                (last[0] + next_xy[0]) * 0.5,
                (last[1] + next_xy[1]) * 0.5,
            )

        last = next_xy

    # Firmware recomputes the final temperature/calibration for the selected xy.
    temperature, tint = xy_to_temperature_tint(last)
    color_matrix = interpolate_color_matrix(temperature)
    return last, temperature, tint, color_matrix


def map_white_matrix(source_xy: Sequence[float], dest_xy: Sequence[float]) -> Matrix3:
    """Firmware 0x016EC568 linearized Bradford white adaptation."""
    w1 = [max(x, 0.0) for x in matvec3(BRADFORD, xy_to_xyz(source_xy))]
    w2 = [max(x, 0.0) for x in matvec3(BRADFORD, xy_to_xyz(dest_xy))]
    ratios = []
    for source, dest in zip(w1, w2):
        value = dest / source if source > 0.0 else 10.0
        ratios.append(max(0.1, min(10.0, value)))
    return matmul3x3(matmul3x3(BRADFORD_INV, diag3(ratios)), BRADFORD)


def _signed16(value: int) -> int:
    v = int(value) & 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


def neutral_from_awb_gains(r_gain: int, g_gain: int, b_gain: int) -> Vector3:
    """Match cm_fill_parameter: signed-16 gain, clamp 1..2000, then 256/gain."""
    gains = []
    for raw in (r_gain, g_gain, b_gain):
        signed = _signed16(raw)
        gains.append(max(1, min(2000, signed)))
    return (256.0 / gains[0], 256.0 / gains[1], 256.0 / gains[2])


def compose_k_m_d(k: Sequence[float], m: Sequence[float], d: Sequence[float]) -> Matrix3:
    """Closed successful-path composition: K x M x diag(D)."""
    return matmul3x3(matmul3x3(k, m), diag3(d))


def dynamic_cc0_float_from_neutral(
    neutral: Sequence[float],
) -> tuple[Matrix3, XY, float, float, Matrix3]:
    """Compute the floating CC0 matrix before Leica's signed-12-bit quantizer."""
    n = _vector3(neutral)
    white_xy, temperature, tint, color_matrix = neutral_to_xy(n)
    adaptation = map_white_matrix(D50_XY, white_xy)
    camera_to_d50 = inverse3x3(matmul3x3(color_matrix, adaptation))
    cc0 = compose_k_m_d(PCS_TO_INTERNAL, camera_to_d50, n)
    return cc0, white_xy, temperature, tint, color_matrix


def dynamic_cc0_float_from_awb(
    r_gain: int, g_gain: int, b_gain: int
) -> tuple[Matrix3, XY, float, float, Matrix3, Vector3]:
    neutral = neutral_from_awb_gains(r_gain, g_gain, b_gain)
    cc0, white_xy, temperature, tint, color_matrix = dynamic_cc0_float_from_neutral(neutral)
    return cc0, white_xy, temperature, tint, color_matrix, neutral


def dynamic_cc0_record_from_awb(r_gain: int, g_gain: int, b_gain: int) -> tuple[int, ...]:
    cc0, _white_xy, temperature, _tint, _color_matrix, _neutral = dynamic_cc0_float_from_awb(
        r_gain, g_gain, b_gain
    )
    return encode_record_words(cc0, temperature)


def round_away(value: float) -> int:
    """C99 round() semantics for finite values: nearest, half away from zero."""
    if not math.isfinite(value):
        raise ValueError("reference encoder expects finite values")
    if value >= 0.0:
        return math.floor(value + 0.5)
    return math.ceil(value - 0.5)


def choose_shift(matrix: Sequence[float]) -> int:
    """Match 0x016F1FB4: test shifts 0..2, otherwise fall through to 3."""
    m = _matrix9(matrix)
    lo = min(m)
    hi = max(m)
    for shift in range(3):
        scale = float(1 << (9 - shift))
        if round_away(lo * scale) >= COEFF_MIN and round_away(hi * scale) <= COEFF_MAX:
            return shift
    return 3


def quantize_coefficients(matrix: Sequence[float], shift: int | None = None) -> tuple[int, ...]:
    m = _matrix9(matrix)
    s = choose_shift(m) if shift is None else int(shift)
    if not 0 <= s <= 3:
        raise ValueError("shift must be in 0..3")
    scale = float(1 << (9 - s))
    return tuple(max(COEFF_MIN, min(COEFF_MAX, round_away(x * scale))) for x in m)


def encode_record_words(matrix: Sequence[float], auxiliary_scalar: float | int) -> tuple[int, ...]:
    """Return the 11 signed int32 words emitted by 0x016F1CB8."""
    m = _matrix9(matrix)
    shift = choose_shift(m)
    coeffs = quantize_coefficients(m, shift)
    aux = round_away(float(auxiliary_scalar))
    return (*coeffs, shift, aux)


def encode_record_bytes(matrix: Sequence[float], auxiliary_scalar: float | int) -> bytes:
    """Return the exact 44-byte little-endian signed-int32 record layout."""
    words = encode_record_words(matrix, auxiliary_scalar)
    return struct.pack("<11i", *words)


def decode_record_bytes(record: bytes) -> tuple[int, ...]:
    if len(record) != 44:
        raise ValueError("CC0 record must be exactly 44 bytes")
    return struct.unpack("<11i", record)
