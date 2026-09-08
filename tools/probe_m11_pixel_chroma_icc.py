#!/usr/bin/env python3
"""Run the comparative M11 pixel-chroma probe with ICC-managed JPEG input."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jpeg_icc_srgb
import probe_m11_pixel_chroma_fast as base


def _out_path(argv: list[str]) -> Path | None:
    try:
        return Path(argv[argv.index("--out") + 1])
    except (ValueError, IndexError):
        return None


def main() -> None:
    base.read_jpeg = lambda p: jpeg_icc_srgb.read_jpeg_icc_to_linear_srgb(
        p, work_long=base.WORK_LONG
    )
    out = _out_path(sys.argv)
    base.main()
    if out and out.exists():
        obj = json.loads(out.read_text())
        obj["schema"] = "m11camera.r2.pixel_chroma_invariant.icc_managed.v4"
        obj["jpeg_colour_management"] = (
            "embedded ICC -> canonical sRGB (relative colorimetric) -> inverse sRGB OETF"
        )
        out.write_text(json.dumps(obj, indent=2) + "\n")


if __name__ == "__main__":
    main()
