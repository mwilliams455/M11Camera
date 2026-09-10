#!/usr/bin/env python3
"""Package canonical M11-P 2.6.1 forensic tables for the Android renderer.

This is a provenance/serialization boundary only. It consumes the exact output
of tools/extract_m11p_forensics.py, hash-gates every photographic source table
against the primary 2.6.1 reproduction, and writes a compact deterministic
binary asset plus a human-readable manifest.

R2YS dependency upper bounds are inclusive in firmware. The Android asset uses
half-open ISO intervals, therefore each raw [lo, hi] dependency is serialized as
[lo, hi + 1). This is evidence-backed by the exact generic range validator.

No fitted values, HDR, local tone mapping, alternate matrices, or visual
corrections are introduced here. The third SRO matrix is carried as audit-only
metadata and is explicitly marked inactive because its consumer placement is
unresolved.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

MAGIC = b"M11APK1A"
FORMAT_VERSION = 1
EXPECTED_FIRMWARE_SHA256 = "0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83"
EXPECTED_HASHES = {
    "category3_CC0_candidate.json": "b3948532d23bf22c22e45d751fc2cc902c86055337a45c5a8bcb12e5202c970e",
    "category13_CC1_candidate.json": "7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb",
    "tone_q12_reconstructed_curves.csv": "b142a9cfcf51e52849e5aac17c224b4de113c79a8ae809b47d8f9fd5fbef658b",
    "gamma_4096_high_nibble_first.csv": "0738ae474494fc83299bd75ba7a4b298950fed49005b6c5693eb0f18c23cfbdc",
    "category24_YCC.json": "6d67e6b601683477e6322d0097d8b2afcc6e015416f93152ec25e8e8ff2fe5f8",
    # Reproduced independently twice from the exact canonical updater. The old
    # 5869... pin was a stale serialization hash, not the extractor's bytes.
    "category42_saturation.json": "59ffbdefdc608285d31b437e7d3c9187e77a894c0a79efa07e521f62c7ddcd54",
    "sro_colour_management.json": "1bd82548e7d64e3151f59bf05458d4216faa5c0f314d8668442eb692e43b576a",
}
HASH_ORDER = tuple(EXPECTED_HASHES)
EXPECTED_CC1_RAW_INCLUSIVE = ((0, 9999), (10000, 19999), (20000, 39999), (40000, 200000))
EXPECTED_CC1_HALF_OPEN = ((0, 10000), (10000, 20000), (20000, 40000), (40000, 200001))
EXPECTED_YCC = ((77, 150, 29), (-43, -85, 128), (128, -107, -21))
EXPECTED_THIRD_SRO = ((212, -165, -71), (-73, 676, 85), (-27, 174, 285))
MODE_RECORDS = (
    (0, "natural", -1, -1, 511, 100),
    (1, "standard", 0, 0, 588, 115),
    (2, "vivid", 1, 1, 665, 130),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text())
    if not isinstance(obj, dict):
        raise ValueError(f"{path}: expected JSON object")
    return obj


def flatten3(matrix: Any, label: str) -> list[int]:
    if not isinstance(matrix, list) or len(matrix) != 3 or any(not isinstance(r, list) or len(r) != 3 for r in matrix):
        raise ValueError(f"{label}: expected 3x3 matrix")
    values = [int(v) for row in matrix for v in row]
    if any(v < -32768 or v > 32767 for v in values):
        raise ValueError(f"{label}: int16 overflow")
    return values


def hash_gate(canonical_dir: Path) -> tuple[dict[str, str], dict[str, Any]]:
    manifest = load_json(canonical_dir / "manifest.json")
    source = manifest.get("source_firmware", {})
    if source.get("sha256") != EXPECTED_FIRMWARE_SHA256:
        raise ValueError(f"unexpected firmware SHA-256: {source.get('sha256')}")
    if not all(manifest.get("canonical_gates", {}).values()):
        raise ValueError("canonical extractor manifest contains a failed evidence gate")

    observed: dict[str, str] = {}
    for name, expected in EXPECTED_HASHES.items():
        path = canonical_dir / name
        if not path.is_file():
            raise ValueError(f"missing canonical asset: {name}")
        digest = sha256_file(path)
        observed[name] = digest
        if digest != expected:
            raise ValueError(f"canonical hash mismatch for {name}: {digest} != {expected}")
        manifest_digest = manifest.get("outputs", {}).get(name, {}).get("sha256")
        if manifest_digest is not None and manifest_digest != expected:
            raise ValueError(f"manifest output hash mismatch for {name}: {manifest_digest}")
    return observed, manifest


def parse_canonical(canonical_dir: Path) -> dict[str, Any]:
    observed_hashes, manifest = hash_gate(canonical_dir)

    cc0j = load_json(canonical_dir / "category3_CC0_candidate.json")
    if int(cc0j.get("q_denominator", 0)) != 512:
        raise ValueError("CC0 denominator is not Q9/512")
    cc0 = flatten3(cc0j.get("matrix_q9"), "CC0")

    cc1j = load_json(canonical_dir / "category13_CC1_candidate.json")
    bands_raw = cc1j.get("bands")
    if not isinstance(bands_raw, list) or len(bands_raw) != 4:
        raise ValueError("Category13 must contain exactly four primary ISO bands")
    bands = []
    for index, band in enumerate(bands_raw):
        if not isinstance(band, dict) or int(band.get("q_denominator", 0)) != 512:
            raise ValueError(f"Category13 band {index}: invalid schema/Q9 denominator")
        iso = band.get("iso_range")
        if not isinstance(iso, list) or len(iso) < 2:
            raise ValueError(f"Category13 band {index}: missing ISO dependency range")
        raw_interval = (int(iso[0]), int(iso[1]))
        if raw_interval != EXPECTED_CC1_RAW_INCLUSIVE[index]:
            raise ValueError(f"Category13 band {index}: unexpected raw inclusive ISO range {raw_interval}")
        if raw_interval[1] == 0xFFFFFFFF:
            raise ValueError("Category13 inclusive upper bound cannot be converted safely")
        interval = (raw_interval[0], raw_interval[1] + 1)
        if interval != EXPECTED_CC1_HALF_OPEN[index]:
            raise ValueError(f"Category13 band {index}: half-open conversion invariant failed")
        bands.append({
            "iso_lower": interval[0],
            "iso_upper_exclusive": interval[1],
            "raw_iso_lower_inclusive": raw_interval[0],
            "raw_iso_upper_inclusive": raw_interval[1],
            "matrix_q9": flatten3(band.get("matrix_q9"), f"CC1 band {index}"),
        })

    tone_rows = list(csv.DictReader((canonical_dir / "tone_q12_reconstructed_curves.csv").open(newline="")))
    if len(tone_rows) != 1024:
        raise ValueError(f"tone table must contain 1024 rows, found {len(tone_rows)}")
    tone_gains: list[list[int]] = [[] for _ in range(7)]
    for index, row in enumerate(tone_rows):
        if int(row["index"]) != index:
            raise ValueError(f"tone row index mismatch at {index}")
        for state in range(-3, 4):
            gain = int(row[f"gain_q12_{state:+d}"])
            if not 0 <= gain <= 65535:
                raise ValueError(f"tone gain outside uint16 at state {state:+d}, row {index}")
            tone_gains[state + 3].append(gain)
    if any(v != 4096 for v in tone_gains[0]):
        raise ValueError("tone state -3 identity invariant failed")

    gamma_rows = list(csv.DictReader((canonical_dir / "gamma_4096_high_nibble_first.csv").open(newline="")))
    if len(gamma_rows) != 4096:
        raise ValueError(f"gamma table must contain 4096 rows, found {len(gamma_rows)}")
    gamma = []
    for index, row in enumerate(gamma_rows):
        if int(row["index"]) != index:
            raise ValueError(f"gamma row index mismatch at {index}")
        value = int(row["output_10bit"])
        if not 0 <= value <= 1023:
            raise ValueError(f"gamma value outside 10-bit range at {index}: {value}")
        gamma.append(value)

    yccj = load_json(canonical_dir / "category24_YCC.json")
    if int(yccj.get("denominator", 0)) != 256:
        raise ValueError("Category24 denominator is not 256")
    ycc_matrix = yccj.get("matrix")
    if tuple(tuple(int(v) for v in row) for row in ycc_matrix) != EXPECTED_YCC:
        raise ValueError("Category24 YCC matrix mismatch")
    ycc = flatten3(ycc_matrix, "YCC")

    satj = load_json(canonical_dir / "category42_saturation.json")
    sat_by_state: dict[int, int] = {}
    for record in satj.get("states", []):
        state = int(record["state"])
        a = int(record["raw_map_offset_plus_8"])
        b = int(record["raw_map_offset_plus_10"])
        if a != b:
            raise ValueError(f"Category42 state {state}: paired saturation fields disagree")
        sat_by_state[state] = a
    for _, name, _, sat_state, expected_field, _ in MODE_RECORDS:
        if sat_by_state.get(sat_state) != expected_field:
            raise ValueError(f"Category42 {name}: field mismatch")

    sroj = load_json(canonical_dir / "sro_colour_management.json")
    words = [int(v) for v in sroj.get("core_words_i32", [])]
    if len(words) != 33:
        raise ValueError("SRO core must contain 33 int32 words")
    third = tuple(tuple(words[22 + row * 3 + col] for col in range(3)) for row in range(3))
    if third != EXPECTED_THIRD_SRO or words[31:33] != [0, 6807]:
        raise ValueError("corrected third SRO record mismatch")

    return {
        "observed_hashes": observed_hashes,
        "manifest": manifest,
        "cc0": cc0,
        "cc1_bands": bands,
        "tone_gains": tone_gains,
        "gamma": gamma,
        "ycc": ycc,
        "tone_luma": [77, 149, 29],
        "sro_words": words,
    }


def build_binary(parsed: dict[str, Any]) -> bytes:
    out = bytearray()
    out += MAGIC
    out += struct.pack(">I", FORMAT_VERSION)
    out += bytes.fromhex(EXPECTED_FIRMWARE_SHA256)
    for name in HASH_ORDER:
        out += bytes.fromhex(parsed["observed_hashes"][name])
    out += struct.pack(">8H", 512, 4096, 256, 1023, 1024, 4096, len(parsed["cc1_bands"]), len(MODE_RECORDS))
    out += struct.pack(">9h", *parsed["cc0"])
    for band in parsed["cc1_bands"]:
        out += struct.pack(">II9h", band["iso_lower"], band["iso_upper_exclusive"], *band["matrix_q9"])
    out += struct.pack(">9h", *parsed["ycc"])
    out += struct.pack(">3H", *parsed["tone_luma"])
    for state_values in parsed["tone_gains"]:
        out += struct.pack(">1024H", *state_values)
    out += struct.pack(">4096H", *parsed["gamma"])
    for mode_id, _name, contrast_state, saturation_state, sat_field, chroma_percent in MODE_RECORDS:
        out += struct.pack(">BbbBHH", mode_id, contrast_state, saturation_state, 0, sat_field, chroma_percent)
    out += struct.pack(">33i", *parsed["sro_words"])
    out += struct.pack(">B3x", 0)
    out += hashlib.sha256(out).digest()
    return bytes(out)


def write_manifest(path: Path, binary_path: Path, binary: bytes, parsed: dict[str, Any], canonical_dir: Path) -> None:
    payload_digest = sha256_bytes(binary[:-32])
    file_digest = sha256_bytes(binary)
    canonical_manifest = canonical_dir / "manifest.json"
    obj = {
        "schema": "m11camera.apk1a.reference_asset.v1",
        "format_magic": MAGIC.decode("ascii"),
        "format_version": FORMAT_VERSION,
        "source_firmware": {
            "version": "M11-P 2.6.1",
            "sha256": EXPECTED_FIRMWARE_SHA256,
            "canonical_manifest_sha256": sha256_file(canonical_manifest),
        },
        "canonical_source_hashes": parsed["observed_hashes"],
        "binary": {
            "name": binary_path.name,
            "size": len(binary),
            "sha256": file_digest,
            "payload_sha256_before_trailer": payload_digest,
            "trailer": "SHA-256 of all preceding binary bytes",
        },
        "fixed_point": {
            "cc0_cc1": "signed Q9 / 512",
            "tone_gain": "unsigned Q12 / 4096",
            "ycc": "signed / 256",
            "gamma_output": "unsigned 10-bit / 1023",
        },
        "counts": {"cc1_iso_bands": 4, "tone_states": 7, "tone_samples": 1024, "gamma_samples": 4096},
        "cc1_iso_ranges": {
            "firmware_raw_inclusive": [list(x) for x in EXPECTED_CC1_RAW_INCLUSIVE],
            "apk_serialized_half_open": [list(x) for x in EXPECTED_CC1_HALF_OPEN],
            "conversion": "upperExclusive = rawUpperInclusive + 1",
            "evidence": "generic firmware R2Y range validator accepts upper endpoint via LS/LE",
        },
        "cc1_iso_bands": parsed["cc1_bands"],
        "mode_mapping": [
            {"id": i, "name": name, "contrast_state": c, "saturation_state": s, "category42_field": field, "chroma_percent": pct}
            for i, name, c, s, field, pct in MODE_RECORDS
        ],
        "sro": {
            "included_for_audit": True,
            "third_record_q9": [list(r) for r in EXPECTED_THIRD_SRO],
            "third_record_metadata": [0, 6807],
            "third_record_active_in_android_pixel_chain": False,
            "consumer_placement_status": "unresolved",
        },
        "category42_hash_note": "59ff... is the exact current extractor serialization reproduced independently; stale 5869... pin retired",
        "no_visual_fitting": True,
        "no_hdr": True,
        "renderer_math_changed": False,
    }
    path.write_text(json.dumps(obj, indent=2) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canonical-dir", type=Path, required=True)
    ap.add_argument("--out-bin", type=Path, required=True)
    ap.add_argument("--out-manifest", type=Path, required=True)
    args = ap.parse_args()
    parsed = parse_canonical(args.canonical_dir)
    binary = build_binary(parsed)
    args.out_bin.parent.mkdir(parents=True, exist_ok=True)
    args.out_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.out_bin.write_bytes(binary)
    write_manifest(args.out_manifest, args.out_bin, binary, parsed, args.canonical_dir)
    print(json.dumps({
        "asset": str(args.out_bin),
        "size": len(binary),
        "sha256": sha256_bytes(binary),
        "payload_sha256": sha256_bytes(binary[:-32]),
        "manifest": str(args.out_manifest),
        "third_sro_active": False,
        "cc1_half_open": [list(x) for x in EXPECTED_CC1_HALF_OPEN],
    }, indent=2))


if __name__ == "__main__":
    main()
