#!/usr/bin/env python3
"""Validate the minimum M11P_color_forensics_v0.3 table set.

This intentionally checks structure rather than asserting the table values are
semantically correct. Stage semantics remain research targets.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

REQUIRED_FILES = (
    "category3_CC0_candidate.json",
    "category13_CC1_candidate.json",
    "tone_q12_reconstructed_curves.csv",
    "gamma_4096_high_nibble_first.csv",
)


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def validate_matrix_json(path: Path, label: str) -> None:
    try:
        obj = json.loads(path.read_text())
    except Exception as exc:
        fail(f"{path}: invalid JSON: {exc}")

    values = obj.get("signed_int16")
    if not isinstance(values, list):
        fail(f"{path}: missing list field signed_int16")
    if len(values) < 10:
        fail(f"{path}: signed_int16 has {len(values)} values; need at least 10")
    if not all(isinstance(v, int) for v in values[:10]):
        fail(f"{path}: first 10 signed_int16 entries must be integers")
    print(f"OK {label}: control + 3x3 candidate matrix present")


def validate_tone(path: Path) -> None:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        fail(f"{path}: no data rows")

    required = {"input_norm"}
    required.update(f"contrast_{c}_output_norm_q12_model" for c in range(-3, 4))
    missing = required.difference(rows[0])
    if missing:
        fail(f"{path}: missing columns {sorted(missing)}")

    # The recovered model describes a 1024-point family. Treat a different row
    # count as a warning so alternate reconstructions can still be inspected.
    if len(rows) != 1024:
        print(f"WARNING tone: expected 1024 rows, found {len(rows)}")
    else:
        print("OK tone: 1024-point contrast family")


def validate_gamma(path: Path) -> None:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        fail(f"{path}: no data rows")

    required = {"input_norm", "output_norm"}
    missing = required.difference(rows[0])
    if missing:
        fail(f"{path}: missing columns {sorted(missing)}")

    if len(rows) != 4096:
        print(f"WARNING gamma: expected 4096 rows, found {len(rows)}")
    else:
        print("OK gamma: 4096-point reconstructed table")


def validate(data_dir: Path) -> None:
    missing = [name for name in REQUIRED_FILES if not (data_dir / name).is_file()]
    if missing:
        fail(
            f"{data_dir}: missing required files: " + ", ".join(missing)
        )

    validate_matrix_json(data_dir / REQUIRED_FILES[0], "CC0")
    validate_matrix_json(data_dir / REQUIRED_FILES[1], "CC1")
    validate_tone(data_dir / REQUIRED_FILES[2])
    validate_gamma(data_dir / REQUIRED_FILES[3])
    print("OK: minimum M11-P forensic table set is structurally usable")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir", type=Path)
    args = ap.parse_args()
    validate(args.data_dir)


if __name__ == "__main__":
    main()
