#!/usr/bin/env python3
"""Materialize canonical M11 firmware extraction into the frozen renderer table contract.

This adapter is deliberately a provenance boundary, not a new image model.
It consumes outputs from tools/extract_m11p_forensics.py and emits the four files
expected by renderer/reference/leica_m11_reference_renderer.py:

- category3_CC0_candidate.json
- category13_CC1_candidate.json
- tone_q12_reconstructed_curves.csv
- gamma_4096_high_nibble_first.csv

The only numerical derivation is the already-recorded Category-6 tone equation:

    output_norm = input_norm * gain_q12 / 4096

No fitting, visual correction, HDR, local tone mapping, or alternate colour
transform is introduced here.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

CANONICAL_FILES = (
    "category3_CC0_candidate.json",
    "category13_CC1_candidate.json",
    "tone_q12_reconstructed_curves.csv",
    "gamma_4096_high_nibble_first.csv",
)
TONE_STATES = tuple(range(-3, 4))
Q12_UNITY = 4096.0


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text())
    if not isinstance(obj, dict):
        raise ValueError(f"{path}: expected JSON object")
    return obj


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def _raw_i16(obj: dict[str, Any], label: str, minimum: int = 10) -> list[int]:
    values = obj.get("raw_i16")
    if not isinstance(values, list) or len(values) < minimum or not all(isinstance(v, int) for v in values):
        raise ValueError(f"{label}: raw_i16 must contain at least {minimum} integer values")
    return values


def _matrix_q9(obj: dict[str, Any], label: str) -> list[list[int]]:
    matrix = obj.get("matrix_q9")
    if (
        not isinstance(matrix, list)
        or len(matrix) != 3
        or any(not isinstance(row, list) or len(row) != 3 for row in matrix)
        or any(not isinstance(v, int) for row in matrix for v in row)
    ):
        raise ValueError(f"{label}: matrix_q9 must be a 3x3 integer matrix")
    return matrix


def _normalize_iso_range(value: Any) -> tuple[int, int] | None:
    """Return the first two dependency words as [lower, upper), if meaningful."""
    if not isinstance(value, list) or len(value) < 2:
        return None
    try:
        lo = int(value[0])
        hi = int(value[1])
    except (TypeError, ValueError):
        return None
    if lo < 0 or hi < 0 or hi <= lo:
        return None
    return lo, hi


def select_cc1_band(bands: list[dict[str, Any]], iso: int | None, band_index: int | None) -> tuple[int, dict[str, Any], str]:
    if not bands:
        raise ValueError("Category13 contains no bands")
    if band_index is not None:
        if not 0 <= band_index < len(bands):
            raise ValueError(f"CC1 band index {band_index} outside 0..{len(bands)-1}")
        return band_index, bands[band_index], "explicit_band_index"
    if iso is None:
        return 0, bands[0], "base_iso_default_first_band"

    for index, band in enumerate(bands):
        interval = _normalize_iso_range(band.get("iso_range"))
        if interval is None:
            continue
        lo, hi = interval
        if lo <= iso < hi:
            return index, band, "iso_range_match"

    # Preserve evidence rather than guessing nearest-band semantics.  If no
    # explicit interval matches, the caller must select a band directly.
    raise ValueError(
        f"ISO {iso} does not match any canonical Category13 iso_range; "
        "use --cc1-band only after inspecting the extracted dependency words"
    )


def materialize_cc0(source: Path, destination: Path) -> dict[str, Any]:
    src = load_json(source)
    raw = _raw_i16(src, "Category3")
    matrix = _matrix_q9(src, "Category3")
    if raw[1:10] != [v for row in matrix for v in row]:
        raise ValueError("Category3 raw_i16[1:10] does not equal matrix_q9")
    out = dict(src)
    out["schema"] = "m11camera.renderer_compat.category3_cc0.v1"
    out["canonical_schema"] = src.get("schema")
    out["signed_int16"] = raw
    out["materialization"] = {
        "operation": "legacy signed_int16 alias from canonical raw_i16",
        "matrix_source": "raw_i16[1:10]",
        "numeric_change": False,
    }
    write_json(destination, out)
    return {
        "canonical_schema": src.get("schema"),
        "matrix_q9": matrix,
        "source_sha256": sha256_file(source),
        "output_sha256": sha256_file(destination),
    }


def materialize_cc1(source: Path, destination: Path, iso: int | None, band_index: int | None) -> dict[str, Any]:
    src = load_json(source)
    bands = src.get("bands")
    if not isinstance(bands, list) or not all(isinstance(x, dict) for x in bands):
        raise ValueError("Category13 bands must be a list of objects")
    index, selected, selection = select_cc1_band(bands, iso, band_index)
    raw = _raw_i16(selected, f"Category13 band {index}")
    matrix = _matrix_q9(selected, f"Category13 band {index}")
    if raw[1:10] != [v for row in matrix for v in row]:
        raise ValueError(f"Category13 band {index} raw_i16[1:10] does not equal matrix_q9")

    out = dict(src)
    out["schema"] = "m11camera.renderer_compat.category13_cc1.v1"
    out["canonical_schema"] = src.get("schema")
    out["signed_int16"] = raw
    out["selected_band_index"] = index
    out["selected_band"] = selected
    out["materialization"] = {
        "operation": "select one canonical ISO band and expose legacy signed_int16 alias",
        "selection_policy": selection,
        "requested_iso": iso,
        "requested_band_index": band_index,
        "selected_iso_range_raw": selected.get("iso_range"),
        "numeric_change": False,
    }
    write_json(destination, out)
    return {
        "canonical_schema": src.get("schema"),
        "selection_policy": selection,
        "requested_iso": iso,
        "selected_band_index": index,
        "selected_iso_range_raw": selected.get("iso_range"),
        "matrix_q9": matrix,
        "source_sha256": sha256_file(source),
        "output_sha256": sha256_file(destination),
    }


def materialize_tone(source: Path, destination: Path) -> dict[str, Any]:
    with source.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 1024:
        raise ValueError(f"tone table must contain 1024 rows, found {len(rows)}")
    required = {"index", "input_norm"} | {f"gain_q12_{state:+d}" for state in TONE_STATES}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"tone table missing columns {sorted(missing)}")

    fields = ["index", "input_norm"]
    fields += [f"gain_q12_{state:+d}" for state in TONE_STATES]
    fields += [f"contrast_{state}_output_norm_q12_model" for state in TONE_STATES]
    derived_minmax: dict[str, list[float]] = {}

    with destination.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        state_values: dict[int, list[float]] = {state: [] for state in TONE_STATES}
        for ordinal, row in enumerate(rows):
            index = int(row["index"])
            input_norm = float(row["input_norm"])
            if index != ordinal:
                raise ValueError(f"tone row {ordinal} has unexpected index {index}")
            if not 0.0 <= input_norm <= 1.0:
                raise ValueError(f"tone row {ordinal} input_norm outside 0..1: {input_norm}")
            out: dict[str, Any] = {"index": index, "input_norm": format(input_norm, ".17g")}
            for state in TONE_STATES:
                gain_key = f"gain_q12_{state:+d}"
                gain = int(row[gain_key])
                if not 0 <= gain <= 65535:
                    raise ValueError(f"tone state {state:+d} row {ordinal}: invalid uint16 gain {gain}")
                output_norm = input_norm * gain / Q12_UNITY
                out[gain_key] = gain
                out[f"contrast_{state}_output_norm_q12_model"] = format(output_norm, ".17g")
                state_values[state].append(output_norm)
            writer.writerow(out)

    # Identity state is an especially high-value invariant: gain=4096 at every
    # node must materialize exactly to the input coordinate within float parsing.
    for ordinal, row in enumerate(rows):
        if int(row["gain_q12_-3"]) != 4096:
            raise ValueError(f"tone -3 identity invariant failed at row {ordinal}")
    for state, values in state_values.items():
        derived_minmax[f"{state:+d}"] = [min(values), max(values)]

    return {
        "source_sha256": sha256_file(source),
        "output_sha256": sha256_file(destination),
        "rows": len(rows),
        "q12_unity": int(Q12_UNITY),
        "derivation": "contrast_output_norm = input_norm * gain_q12 / 4096",
        "identity_state": -3,
        "identity_state_all_gain_q12_4096": True,
        "derived_output_minmax": derived_minmax,
    }


def materialize_gamma(source: Path, destination: Path) -> dict[str, Any]:
    shutil.copyfile(source, destination)
    source_hash = sha256_file(source)
    output_hash = sha256_file(destination)
    if source_hash != output_hash:
        raise ValueError("gamma copy hash mismatch")
    return {
        "source_sha256": source_hash,
        "output_sha256": output_hash,
        "operation": "byte-for-byte copy; canonical schema already matches renderer contract",
        "numeric_change": False,
    }


def materialize(source_dir: Path, out_dir: Path, iso: int | None = None, band_index: int | None = None) -> dict[str, Any]:
    missing = [name for name in CANONICAL_FILES if not (source_dir / name).is_file()]
    if missing:
        raise ValueError(f"canonical extraction is incomplete: {', '.join(missing)}")
    if iso is not None and band_index is not None:
        raise ValueError("use only one of iso or band_index")
    if iso is not None and iso < 0:
        raise ValueError("ISO must be non-negative")

    out_dir.mkdir(parents=True, exist_ok=True)
    cc0 = materialize_cc0(source_dir / CANONICAL_FILES[0], out_dir / CANONICAL_FILES[0])
    cc1 = materialize_cc1(source_dir / CANONICAL_FILES[1], out_dir / CANONICAL_FILES[1], iso, band_index)
    tone = materialize_tone(source_dir / CANONICAL_FILES[2], out_dir / CANONICAL_FILES[2])
    gamma = materialize_gamma(source_dir / CANONICAL_FILES[3], out_dir / CANONICAL_FILES[3])

    manifest = {
        "schema": "m11camera.renderer_compat.materialized_reference_tables.v1",
        "purpose": "canonical firmware extraction -> frozen reference-renderer table contract",
        "source_directory": str(source_dir),
        "output_directory": str(out_dir),
        "no_visual_fitting": True,
        "no_hdr": True,
        "renderer_math_changed": False,
        "tone_equation_evidence": "recorded M11 finding: Yout ~= (Yin * Gain[Yin]) >> 12",
        "tables": {"cc0": cc0, "cc1": cc1, "tone": tone, "gamma": gamma},
    }
    manifest_path = out_dir / "materialized_reference_tables_manifest.json"
    write_json(manifest_path, manifest)
    manifest["manifest_sha256"] = sha256_file(manifest_path)
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-dir", type=Path, required=True, help="canonical extract_m11p_forensics.py output")
    ap.add_argument("--out-dir", type=Path, required=True)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--iso", type=int, help="select Category13 band by canonical extracted ISO dependency range")
    group.add_argument("--cc1-band", type=int, help="explicit Category13 band index after inspecting extraction")
    args = ap.parse_args()

    result = materialize(args.source_dir, args.out_dir, args.iso, args.cc1_band)
    print(json.dumps({
        "out_dir": str(args.out_dir),
        "cc1_selected_band": result["tables"]["cc1"]["selected_band_index"],
        "cc1_selection_policy": result["tables"]["cc1"]["selection_policy"],
        "manifest_sha256": result["manifest_sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
