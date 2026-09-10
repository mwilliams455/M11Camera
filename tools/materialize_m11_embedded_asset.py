#!/usr/bin/env python3
"""Materialize the pinned RENDER1A reference binary into Android assets.

The repository stores a deterministic gzip+base64 transport so Git text tooling
can carry the derived firmware tables. This script reconstructs the exact binary
and refuses output unless its size and SHA-256 match the locally reproduced
canonical M11-P 2.6.1 asset.
"""
from __future__ import annotations
import argparse, base64, gzip, hashlib
from pathlib import Path

EXPECTED_SIZE = 23150
EXPECTED_SHA256 = "54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219"
DEFAULT_SOURCE = Path("app/src/main/reference-assets/m11_reference_tables_v1.bin.gz.b64")
DEFAULT_DEST = Path("app/src/main/assets/m11_reference_tables_v1.bin")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    a = ap.parse_args()
    compressed = base64.b64decode(a.source.read_text(), validate=False)
    binary = gzip.decompress(compressed)
    digest = hashlib.sha256(binary).hexdigest()
    if len(binary) != EXPECTED_SIZE:
        raise ValueError(f"M11 embedded asset size mismatch: {len(binary)} != {EXPECTED_SIZE}")
    if digest != EXPECTED_SHA256:
        raise ValueError(f"M11 embedded asset SHA-256 mismatch: {digest} != {EXPECTED_SHA256}")
    a.dest.parent.mkdir(parents=True, exist_ok=True)
    a.dest.write_bytes(binary)
    print(f"{a.dest} size={len(binary)} sha256={digest}")


if __name__ == "__main__":
    main()
