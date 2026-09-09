#!/usr/bin/env python3
"""Fail closed unless the Python RAW oracle uses the frozen decoder identity."""
from __future__ import annotations

import json

EXPECTED_RAWPY = "0.27.1"
EXPECTED_LIBRAW = (0, 22, 1)


def normalize_libraw_version(value) -> tuple[int, int, int]:
    if isinstance(value, str):
        parts = value.strip().split(".")
    else:
        try:
            parts = list(value)
        except TypeError as exc:
            raise RuntimeError(f"unsupported rawpy.libraw_version value: {value!r}") from exc
    if len(parts) < 3:
        raise RuntimeError(f"incomplete rawpy.libraw_version value: {value!r}")
    return tuple(int(x) for x in parts[:3])


def main() -> None:
    import rawpy

    rawpy_version = str(getattr(rawpy, "__version__", ""))
    if rawpy_version != EXPECTED_RAWPY:
        raise SystemExit(f"rawpy version mismatch: {rawpy_version!r} != {EXPECTED_RAWPY!r}")

    if not hasattr(rawpy, "libraw_version"):
        raise SystemExit("rawpy does not expose runtime libraw_version; RAW parity identity is unprovable")
    libraw_version = normalize_libraw_version(rawpy.libraw_version)
    if libraw_version != EXPECTED_LIBRAW:
        raise SystemExit(f"LibRaw runtime mismatch: {libraw_version!r} != {EXPECTED_LIBRAW!r}")

    print(json.dumps({
        "schema": "m11camera.raw_oracle_environment.v1",
        "rawpy": rawpy_version,
        "libraw": list(libraw_version),
        "demosaic": "AHD",
        "identity_gate": True,
    }, indent=2))


if __name__ == "__main__":
    main()
