#!/usr/bin/env python3
"""Generate a tiny deterministic Bayer DNG for LibRaw open/identify CI only.

This fixture contains no Leica or Xiaomi proprietary image data. It exists to
prove TIFF/DNG identification through APK1A's fd-backed LibRaw datastream. The
RAW pixels are synthetic and must never be used for photographic parity claims.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4}


def pack_values(tiff_type: int, values) -> bytes:
    if tiff_type == 1:  # BYTE
        return bytes(values)
    if tiff_type == 2:  # ASCII
        if isinstance(values, str):
            values = values.encode("ascii")
        data = bytes(values)
        return data if data.endswith(b"\0") else data + b"\0"
    if tiff_type == 3:  # SHORT
        return struct.pack("<" + "H" * len(values), *values)
    if tiff_type == 4:  # LONG
        return struct.pack("<" + "I" * len(values), *values)
    raise ValueError(f"unsupported TIFF type {tiff_type}")


def build_dng() -> bytes:
    # LibRaw's identify/open path rejects RAW dimensions below 22 pixels. Keep
    # this fixture safely above that structural floor while still microscopic.
    width = 32
    height = 32
    raw = bytearray()
    for y in range(height):
        for x in range(width):
            value = 64 + ((y * width + x) * 3) % 700
            raw += struct.pack("<H", value)

    # (tag, TIFF type, values). Values are intentionally minimal but standards-
    # shaped enough for LibRaw's TIFF/DNG identify path. Pixel decoding is not
    # part of this fixture's purpose.
    specs = [
        (256, 4, [width]),                       # ImageWidth
        (257, 4, [height]),                      # ImageLength
        (258, 3, [16]),                          # BitsPerSample
        (259, 3, [1]),                           # Compression = none
        (262, 3, [32803]),                       # PhotometricInterpretation = CFA
        (271, 2, "Xiaomi"),                      # Make
        (272, 2, "APK1A Synthetic DNG"),         # Model
        (273, 4, [0]),                           # StripOffsets, patched below
        (274, 3, [1]),                           # Orientation
        (277, 3, [1]),                           # SamplesPerPixel
        (278, 4, [height]),                      # RowsPerStrip
        (279, 4, [len(raw)]),                    # StripByteCounts
        (284, 3, [1]),                           # PlanarConfiguration
        (33421, 3, [2, 2]),                      # CFARepeatPatternDim
        (33422, 1, [0, 1, 1, 2]),                # CFAPattern RGGB
        (50706, 1, [1, 4, 0, 0]),                # DNGVersion
        (50707, 1, [1, 3, 0, 0]),                # DNGBackwardVersion
        (50708, 2, "Xiaomi APK1A Synthetic RAW"),# UniqueCameraModel
        (50713, 3, [1, 1]),                      # BlackLevelRepeatDim
        (50714, 4, [64]),                        # BlackLevel
        (50717, 4, [1023]),                      # WhiteLevel
        (50778, 3, [21]),                        # CalibrationIlluminant1 = D65
    ]
    specs.sort(key=lambda item: item[0])

    count = len(specs)
    ifd_offset = 8
    ifd_end = ifd_offset + 2 + count * 12 + 4
    extra = bytearray()
    entries = []

    # First assign all non-inline payload offsets. StripOffsets is inline and is
    # patched only after those payload locations are known.
    for tag, tiff_type, values in specs:
        data = pack_values(tiff_type, values)
        item_count = len(data) // TYPE_SIZE[tiff_type]
        if tiff_type == 2:
            item_count = len(data)
        if len(data) <= 4:
            field = data.ljust(4, b"\0")
        else:
            if (ifd_end + len(extra)) & 1:
                extra += b"\0"
            offset = ifd_end + len(extra)
            field = struct.pack("<I", offset)
            extra += data
        entries.append([tag, tiff_type, item_count, field])

    if (ifd_end + len(extra)) & 1:
        extra += b"\0"
    raw_offset = ifd_end + len(extra)

    for entry in entries:
        if entry[0] == 273:
            entry[3] = struct.pack("<I", raw_offset)
            break

    out = bytearray(b"II")
    out += struct.pack("<H", 42)
    out += struct.pack("<I", ifd_offset)
    out += struct.pack("<H", count)
    for tag, tiff_type, item_count, field in entries:
        out += struct.pack("<HHI", tag, tiff_type, item_count)
        out += field
    out += struct.pack("<I", 0)  # no next IFD
    out += extra
    if len(out) != raw_offset:
        raise AssertionError((len(out), raw_offset))
    out += raw
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    payload = build_dng()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(payload)
    print(f"synthetic_dng={args.out}")
    print(f"size={len(payload)}")
    print(f"sha256={hashlib.sha256(payload).hexdigest()}")
    print("synthetic_only=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
