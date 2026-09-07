#!/usr/bin/env python3
"""Decompress Leica M11/M11-P firmware payloads used by the forensic work.

Recovered from the original M11 research script and parameterized so the public
repo does not assume /mnt/data paths. The firmware itself is deliberately not
stored in this repository.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


def decompress_firmware(src: Path, outp: Path) -> None:
    d = src.read_bytes()
    if len(d) < 0x28:
        raise ValueError("firmware is too small to contain the observed M11 header")

    body_off = struct.unpack_from("<I", d, 4)[0]
    unpacked_size = struct.unpack_from("<I", d, 0x0C)[0]
    packed_size = struct.unpack_from("<I", d, 0x14)[0]
    md5_expected = d[0x18:0x28]

    if body_off >= len(d):
        raise ValueError(f"body offset {body_off:#x} lies outside firmware")
    if body_off + packed_size > len(d):
        raise ValueError("packed payload extends beyond firmware length")

    body = d[body_off : body_off + packed_size]
    if not body:
        raise ValueError("empty packed body")

    actual_md5 = hashlib.md5(body).digest()
    print(
        "body_off",
        hex(body_off),
        "packed",
        packed_size,
        "unpacked",
        unpacked_size,
        "magic",
        hex(body[0]),
    )
    print("md5 expected", md5_expected.hex(), "actual", actual_md5.hex())
    if actual_md5 != md5_expected:
        print("WARNING: packed-body MD5 does not match header")

    magic = body[0]
    out = bytearray()
    i = 1
    n = len(body)
    refs = escapes = literals = 0

    while i < n:
        b = body[i]
        if b != magic:
            out.append(b)
            i += 1
            literals += 1
        else:
            if i + 1 >= n:
                raise ValueError(f"truncated marker at {i:#x}")
            if body[i + 1] == 0:
                out.append(magic)
                i += 2
                escapes += 1
                continue

            j = i + 1
            a = body[j]
            j += 1
            if a & 0x80:
                if j >= n:
                    raise ValueError("truncated length")
                length = ((a & 0x7F) << 7) + body[j]
                j += 1
            else:
                length = a

            if j >= n:
                raise ValueError("truncated offset")
            a = body[j]
            j += 1
            if a & 0x80:
                if j >= n:
                    raise ValueError("truncated extended offset")
                offset = ((a & 0x7F) << 7) + body[j]
                j += 1
            else:
                offset = a

            if offset == 0 or offset > len(out):
                raise ValueError(
                    f"bad offset {offset} at input {i:#x}, "
                    f"out {len(out):#x}, len {length}"
                )

            # The original compressor appeared to emit non-overlapping refs, but
            # copy byte-by-byte so overlapping LZ-style references are safe too.
            start = len(out) - offset
            for k in range(length):
                out.append(out[start + k])
            i = j
            refs += 1

        if len(out) > unpacked_size + 1024:
            raise ValueError(
                f"output exceeded expected size {len(out)} > {unpacked_size}"
            )

    print(
        "done: input consumed",
        i,
        n,
        "output",
        len(out),
        "expected",
        unpacked_size,
        "refs",
        refs,
        "escapes",
        escapes,
        "literals",
        literals,
    )

    if len(out) != unpacked_size:
        print(
            f"WARNING: decompressed length {len(out)} differs from header "
            f"value {unpacked_size}"
        )

    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(out)
    print("wrote", outp)
    print("first 128", out[:128].hex())


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Decompress the packed payload from an M11/M11-P firmware file."
    )
    ap.add_argument("firmware", type=Path, help="path to Leica .FW file")
    ap.add_argument(
        "--output",
        "-o",
        type=Path,
        help="output path; defaults to <firmware-stem>_unpacked.bin",
    )
    args = ap.parse_args()

    output = args.output or args.firmware.with_name(
        f"{args.firmware.stem}_unpacked.bin"
    )
    decompress_firmware(args.firmware, output)


if __name__ == "__main__":
    main()
