#!/usr/bin/env python3
"""Dump rawpy 0.27.1 unpacked mosaic and frozen AHD output for exact CI cmp."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import rawpy

EXPECTED_RAWPY = "0.27.1"
EXPECTED_LIBRAW = (0, 22, 1)


def frozen_params() -> rawpy.Params:
    return rawpy.Params(
        demosaic_algorithm=rawpy.DemosaicAlgorithm.AHD,
        half_size=False,
        four_color_rgb=False,
        use_camera_wb=False,
        use_auto_wb=False,
        user_wb=[1.0, 1.0, 1.0, 1.0],
        output_color=rawpy.ColorSpace.raw,
        output_bps=16,
        no_auto_scale=False,
        no_auto_bright=True,
        adjust_maximum_thr=0.0,
        bright=1.0,
        highlight_mode=rawpy.HighlightMode.Clip,
        gamma=(1.0, 1.0),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dng", type=Path)
    ap.add_argument("out_dir", type=Path)
    args = ap.parse_args()

    if rawpy.__version__ != EXPECTED_RAWPY:
        raise SystemExit(f"rawpy identity mismatch: {rawpy.__version__}")
    runtime = tuple(int(v) for v in rawpy.libraw_version)
    if runtime != EXPECTED_LIBRAW:
        raise SystemExit(f"LibRaw identity mismatch: {runtime}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with rawpy.imread(str(args.dng)) as raw:
        # Accessing raw_image_visible invokes the same ensure_unpack() boundary
        # that rawpy postprocess uses. Copy before processing mutates state.
        mosaic = np.asarray(raw.raw_image_visible, dtype=np.uint16).copy()
        (args.out_dir / "mosaic_u16le.bin").write_bytes(
            mosaic.astype("<u2", copy=False).tobytes(order="C")
        )

        ahd = raw.postprocess(params=frozen_params())
        if ahd.dtype != np.uint16:
            raise SystemExit(f"unexpected processed dtype: {ahd.dtype}")
        (args.out_dir / "ahd_u16le.bin").write_bytes(
            ahd.astype("<u2", copy=False).tobytes(order="C")
        )

        meta = [
            "schema=m11camera.raw_pixel_parity.v1",
            "producer=rawpy",
            f"rawpyVersion={rawpy.__version__}",
            "librawVersion=0.22.1",
            f"mosaicWidth={mosaic.shape[1]}",
            f"mosaicHeight={mosaic.shape[0]}",
            f"outputWidth={ahd.shape[1]}",
            f"outputHeight={ahd.shape[0]}",
            f"outputColors={ahd.shape[2] if ahd.ndim == 3 else 1}",
            "outputBits=16",
            f"outputBytes={ahd.nbytes}",
            "demosaic=AHD",
            "decodeInvoked=true",
            "m11RendererInvoked=false",
        ]
        (args.out_dir / "metadata.txt").write_text("\n".join(meta) + "\n")

    print("rawpy_pixel_parity_dump=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
