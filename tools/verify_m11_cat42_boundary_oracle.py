#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CspMap:
    offsets: tuple[int, int, int, int]
    gains: tuple[int, int, int, int]
    borders: tuple[int, int, int]


STANDARD = CspMap(
    offsets=(258, 588, 588, 505),
    gains=(26, 0, -4, -20),
    borders=(100, 771, 922),
)


def floor_div8_arithmetic_shift_equivalent(value: int) -> int:
    """Portable mathematical floor(value / 8), matching arithmetic >>3."""
    return value // 8


def evaluate_scale_code(reference_code: int, mapping: CspMap = STANDARD) -> tuple[int, int]:
    """Current bounded RENDER1H candidate: right-open, local Q3, direct code."""
    if not 0 <= reference_code <= 1023:
        raise ValueError("reference_code must be a bounded 10-bit code")

    b0, b1, b2 = mapping.borders
    if reference_code < b0:
        region, origin = 0, 0
    elif reference_code < b1:
        region, origin = 1, b0
    elif reference_code < b2:
        region, origin = 2, b1
    else:
        region, origin = 3, b2

    product = mapping.gains[region] * (reference_code - origin)
    delta = floor_div8_arithmetic_shift_equivalent(product)
    code = max(0, min(1023, mapping.offsets[region] + delta))
    return region, code


def scale_from_code(code: int) -> float:
    if not 0 <= code <= 1023:
        raise ValueError("CSY scale code outside 10-bit range")
    return code / 512.0


def main() -> None:
    # These are the seam points where comparator ownership and signed negative
    # division matter. Keep this list deliberately explicit and reviewable.
    expected = {
        0: (0, 258),
        99: (0, 579),
        100: (1, 588),
        101: (1, 588),
        770: (1, 588),
        771: (2, 588),
        772: (2, 587),
        921: (2, 513),
        922: (3, 505),
        923: (3, 502),
        1023: (3, 252),
    }

    for reference_code, want in expected.items():
        got = evaluate_scale_code(reference_code)
        if got != want:
            raise AssertionError(f"Y={reference_code}: expected {want}, got {got}")

    # Explicit negative non-multiple-of-eight products: this distinguishes the
    # retained arithmetic-shift/floor candidate from truncation toward zero.
    signed_cases = {
        -1: -1,
        -4: -1,
        -7: -1,
        -8: -1,
        -9: -2,
        -20: -3,
        -28: -4,
    }
    for product, want in signed_cases.items():
        got = floor_div8_arithmetic_shift_equivalent(product)
        if got != want:
            raise AssertionError(f"floor_div8({product}): expected {want}, got {got}")

    # Direct Q9 is zero-preserving. This is the key M11 scale-encoding closure
    # that rules out an unconditional register +1 interpretation.
    if scale_from_code(0) != 0.0:
        raise AssertionError("direct Q9 must preserve code zero as exact zero")
    if scale_from_code(512) != 1.0:
        raise AssertionError("direct Q9 code 512 must be exact unity")
    if scale_from_code(588) != 1.1484375:
        raise AssertionError("Standard plateau code 588 decoding drifted")

    # Audit the build-time overlay so the oracle cannot silently diverge from
    # the implementation that materializes RENDER1H/RENDER1I.
    overlay = Path("tools/apply_render1h_cat42yq3a.py").read_text()
    required = [
        "cat42_reference_code < 100",
        "cat42_reference_code < 771",
        "cat42_reference_code < 922",
        "cat42_gain * (cat42_reference_code - cat42_origin)",
        "-(((-cat42_product) + 7) / 8)",
        "static_cast<double>(cat42_scale_code) / 512.0",
        "category42IntegerConventionHardwareExact=false",
        "category42RegisterPlusOneScaleSemanticsApplied=false",
    ]
    missing = [marker for marker in required if marker not in overlay]
    if missing:
        raise AssertionError(f"RENDER1H overlay drifted from boundary oracle: {missing}")

    print("cat42BoundaryOracle=PASS")
    print("candidate=right_open_local_Q3_floor_direct_Q9")
    print("hardwareExact=false")
    for reference_code in expected:
        region, code = evaluate_scale_code(reference_code)
        print(
            f"Y={reference_code:4d} region={region} scaleCode={code:4d} "
            f"scale={scale_from_code(code):.9f}"
        )


if __name__ == "__main__":
    main()
