#!/usr/bin/env python3
"""Decompress Leica M11/M11-P firmware payloads used by the forensic work.

The M11/M11-P updater uses one marker byte followed by literal bytes or
back-references. Length and offset values are unsigned base-128 continuation
integers (7 payload bits per byte, most-significant group first). This matters:
real M11-P 2.6.1 contains three-byte values such as ``81 80 00`` = 16384.

The firmware itself is deliberately not stored in this repository.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


def read_base128_uint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode one big-endian 7-bit continuation integer.

    Each byte contributes 7 payload bits. Bit 7 means another byte follows.
    Examples from genuine M11-P 2.6.1 firmware:

    - ``10``       -> 16
    - ``90 00``    -> 2048
    - ``a0 00``    -> 4096
    - ``c0 00``    -> 8192
    - ``81 80 00`` -> 16384
    """
    value = 0
    groups = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated base-128 integer")
        byte = buf[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        groups += 1
        # Values in the observed format are bounded to 16-bit copy lengths /
        # distances. Keep a defensive guard so malformed firmware cannot create
        # an unbounded integer loop.
        if groups > 5:
            raise ValueError("base-128 integer is implausibly long")
        if not (byte & 0x80):
            return value, pos


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
    max_length = max_offset = 0

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
            length, j = read_base128_uint(body, j)
            offset, j = read_base128_uint(body, j)

            if offset == 0 or offset > len(out):
                raise ValueError(
                    f"bad offset {offset} at input {i:#x}, "
                    f"out {len(out):#x}, len {length}"
                )

            # Copy from the current output tail rather than from one fixed slice.
            # This correctly supports overlapping LZ-style references.
            for _ in range(length):
                out.append(out[-offset])
            i = j
            refs += 1
            max_length = max(max_length, length)
            max_offset = max(max_offset, offset)

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
        "max_length",
        max_length,
        "max_offset",
        max_offset,
    )

    if len(out) != unpacked_size:
        print(
            f"WARNING: decompressed length {len(out)} differs from header "
            f"value {unpacked_size}"
        )

    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(out)
    print("wrote", outp)
    print("sha256", hashlib.sha256(out).hexdigest())
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
