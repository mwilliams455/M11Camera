#!/usr/bin/env python3
"""Run the M11 tone-domain consistency probe with ICC-managed JPEG input."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jpeg_icc_srgb
import probe_m11_pixel_chroma_fast as base

# Patch the shared JPEG reader before importing the tone-domain module, which
# imports the same base module object from sys.modules.
base.read_jpeg = lambda p: jpeg_icc_srgb.read_jpeg_icc_to_linear_srgb(
    p, work_long=base.WORK_LONG
)
import probe_m11_tone_domain_consistency as tone  # noqa: E402


def _out_path(argv: list[str]) -> Path | None:
    try:
        return Path(argv[argv.index("--out") + 1])
    except (ValueError, IndexError):
        return None


def main() -> None:
    out = _out_path(sys.argv)
    tone.main()
    if out and out.exists():
        obj = json.loads(out.read_text())
        obj["schema"] = "m11camera.r2.tone_domain_consistency.icc_managed.v2"
        obj["jpeg_colour_management"] = (
            "embedded ICC -> canonical sRGB (relative colorimetric) -> inverse sRGB OETF"
        )
        out.write_text(json.dumps(obj, indent=2) + "\n")


if __name__ == "__main__":
    main()
