#!/usr/bin/env python3
"""ICC-aware JPEG ingest for genuine Leica M11 sample JPEGs.

Pillow's plain ``convert('RGB')`` does not apply an embedded ICC profile.  The
M11 matched JPEG corpus embeds ICC profiles, so treating those code values as
already-sRGB can corrupt colour/chroma forensic comparisons.

This helper:
1. reads the embedded source ICC profile;
2. applies EXIF orientation;
3. converts source-profile RGB -> canonical sRGB with Pillow ImageCms;
4. downsizes in sRGB code-value space;
5. decodes the standard sRGB OETF to linear sRGB.

Only profile metadata/hash are emitted in diagnostics, never the ICC bytes.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

import numpy as np
from PIL import Image, ImageCms, ImageOps

WORK_LONG = 1400


def srgb_decode(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, np.float32)
    return np.where(
        x <= 0.04045,
        x / 12.92,
        ((x + 0.055) / 1.055) ** 2.4,
    ).astype(np.float32)


def _safe_profile_value(fn, profile):
    try:
        value = fn(profile)
        return str(value).strip() if value is not None else None
    except Exception:
        return None


def read_jpeg_icc_to_linear_srgb(jpg: str | Path, work_long: int = WORK_LONG):
    src = Image.open(jpg)
    exif_orientation = src.getexif().get(274)
    icc_bytes = src.info.get("icc_profile")

    oriented = ImageOps.exif_transpose(src).convert("RGB")
    native = (oriented.height, oriented.width, 3)

    diag = {
        "jpeg_native_shape_oriented": list(native),
        "jpeg_exif_orientation": exif_orientation,
        "icc_profile_present": bool(icc_bytes),
        "icc_converted_to_srgb": False,
        "icc_profile_sha256": hashlib.sha256(icc_bytes).hexdigest() if icc_bytes else None,
        "icc_profile_description": None,
        "icc_profile_name": None,
        "icc_profile_info": None,
        "icc_default_intent": None,
        "icc_missing_policy": "assume_sRGB_only_when_no_embedded_profile",
    }

    if icc_bytes:
        source_profile = ImageCms.ImageCmsProfile(io.BytesIO(icc_bytes))
        srgb_profile = ImageCms.createProfile("sRGB")
        diag["icc_profile_description"] = _safe_profile_value(ImageCms.getProfileDescription, source_profile)
        diag["icc_profile_name"] = _safe_profile_value(ImageCms.getProfileName, source_profile)
        diag["icc_profile_info"] = _safe_profile_value(ImageCms.getProfileInfo, source_profile)
        try:
            diag["icc_default_intent"] = int(ImageCms.getDefaultIntent(source_profile))
        except Exception:
            pass

        # Relative colorimetric is the default intent for profileToProfile and is
        # deterministic for the forensic comparison.  No black-point compensation
        # or perceptual gamut remapping is injected here.
        oriented = ImageCms.profileToProfile(
            oriented,
            source_profile,
            srgb_profile,
            renderingIntent=0,
            outputMode="RGB",
        )
        diag["icc_converted_to_srgb"] = True

    oriented.thumbnail((work_long, work_long), Image.Resampling.LANCZOS)
    arr = np.asarray(oriented, np.float32) * (1.0 / 255.0)
    diag["working_shape"] = list(arr.shape)
    return srgb_decode(arr), diag
