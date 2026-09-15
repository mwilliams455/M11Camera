#!/usr/bin/env python3
"""Firmware-faithful reference helpers for the closed M11 ColorSpec CC0 boundary.

This module intentionally stops at the proven boundary.  It does not guess the
remaining upstream ColorSpec inputs.  Callers provide the floating 3x3 matrix
(or the K, M, D factors once those are known) and this code reproduces the
matrix multiplication and 44-byte CC0 quantization record traced in M11-P 2.6.1.
"""
from __future__ import annotations

import math
import struct
from typing import Iterable, Sequence

Matrix3 = tuple[float, float, float, float, float, float, float, float, float]

COEFF_MIN = -2048
COEFF_MAX = 2047


def _matrix9(values: Iterable[float]) -> Matrix3:
    v = tuple(float(x) for x in values)
    if len(v) != 9:
        raise ValueError("expected 9 matrix coefficients")
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


def diag3(values: Sequence[float]) -> Matrix3:
    if len(values) != 3:
        raise ValueError("expected 3 diagonal values")
    x, y, z = (float(v) for v in values)
    return (x, 0.0, 0.0, 0.0, y, 0.0, 0.0, 0.0, z)


def compose_k_m_d(k: Sequence[float], m: Sequence[float], d: Sequence[float]) -> Matrix3:
    """Closed successful-path composition: K x M x diag(D)."""
    return matmul3x3(matmul3x3(k, m), diag3(d))


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
