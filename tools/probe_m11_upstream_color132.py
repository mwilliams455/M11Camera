#!/usr/bin/env python3
"""Locate the recorded M11 upstream 132-byte colour-management structure.

The prior M11-P investigation recorded a 33 x signed-int32 structure containing
three distinctive 3x3 integer matrices:

* CM1: exact Q12 match to genuine M11 DNG ColorMatrix1 (Standard Light A)
* CM2: exact Q12 match to genuine M11 DNG ColorMatrix2 (D65)
* an additional 3x3 integer matrix whose scaling/consumer remains unresolved

This probe searches the decompressed official firmware and every regular file in
the two recorded ROMFS images for those exact integer signatures.  It emits only
small derived forensic summaries: offsets, candidate 33-word windows and hashes.
It never writes arbitrary firmware payload bytes to the repository/artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from itertools import product
from pathlib import Path
from typing import Iterable

from m11_romfs_probe import RECORDED_LANDMARKS, entry_bytes, parse_romfs, walk_romfs

STRUCT_BYTES = 132
STRUCT_WORDS = STRUCT_BYTES // 4

SIGNATURES: dict[str, tuple[int, ...]] = {
    "cm1_q12": (
        2358, -546, -66,
        -2488, 6300, 1785,
        -403, 797, 3504,
    ),
    "cm2_q12": (
        1700, -326, -200,
        -2354, 5409, 974,
        -612, 976, 2276,
    ),
    "extra_matrix": (
        212, -165, -71,
        -73, 676, 85,
        -27, 174, 285,
    ),
}

RECORDED_TEMPERATURES = (2850, 6807)


def pack_words(words: Iterable[int], endian: str) -> bytes:
    values = tuple(int(x) for x in words)
    prefix = "<" if endian == "little" else ">"
    return struct.pack(prefix + "i" * len(values), *values)


def unpack_words(data: bytes, endian: str) -> list[int]:
    if len(data) % 4:
        raise ValueError("int32 payload length must be a multiple of four")
    prefix = "<" if endian == "little" else ">"
    return list(struct.unpack(prefix + "i" * (len(data) // 4), data))


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + 1


def signature_hits(data: bytes, endian: str) -> dict[str, list[int]]:
    return {
        name: find_all(data, pack_words(words, endian))
        for name, words in SIGNATURES.items()
    }


def _align_up4(value: int) -> int:
    return (value + 3) & ~3


def _align_down4(value: int) -> int:
    return value & ~3


def candidate_windows(data: bytes, endian: str, hits: dict[str, list[int]]) -> list[dict]:
    """Return every aligned 132-byte window containing one hit of each signature."""
    names = tuple(SIGNATURES)
    if any(not hits.get(name) for name in names):
        return []

    sig_lengths = {name: len(SIGNATURES[name]) * 4 for name in names}
    candidates: dict[tuple[int, tuple[int, ...]], dict] = {}

    for chosen in product(*(hits[name] for name in names)):
        chosen_map = dict(zip(names, chosen))
        latest_end = max(chosen_map[name] + sig_lengths[name] for name in names)
        earliest_start = min(chosen_map.values())
        start_lo = max(0, latest_end - STRUCT_BYTES)
        start_hi = min(earliest_start, len(data) - STRUCT_BYTES)
        start_lo = _align_up4(start_lo)
        start_hi = _align_down4(start_hi)
        if start_lo > start_hi:
            continue

        for start in range(start_lo, start_hi + 1, 4):
            end = start + STRUCT_BYTES
            if any(
                not (start <= chosen_map[name] and chosen_map[name] + sig_lengths[name] <= end)
                for name in names
            ):
                continue
            words = unpack_words(data[start:end], endian)
            offsets_words = {
                name: (chosen_map[name] - start) // 4
                for name in names
            }
            temp_positions = {
                str(temp): [i for i, value in enumerate(words) if value == temp]
                for temp in RECORDED_TEMPERATURES
            }
            key = (start, tuple(offsets_words[name] for name in names))
            candidates[key] = {
                "start": start,
                "end": end,
                "signature_word_offsets": offsets_words,
                "recorded_temperature_word_positions": temp_positions,
                "contains_both_recorded_temperatures": all(temp_positions[str(t)] for t in RECORDED_TEMPERATURES),
                "words": words,
                "window_sha256": hashlib.sha256(data[start:end]).hexdigest(),
            }

    return sorted(
        candidates.values(),
        key=lambda x: (
            not x["contains_both_recorded_temperatures"],
            x["start"],
            tuple(x["signature_word_offsets"].values()),
        ),
    )


def scan_payload(data: bytes) -> list[dict]:
    results: list[dict] = []
    for endian in ("little", "big"):
        hits = signature_hits(data, endian)
        if any(hits.values()):
            results.append(
                {
                    "endian": endian,
                    "signature_hits": hits,
                    "candidate_windows": candidate_windows(data, endian, hits),
                }
            )
    return results


def scan_romfs(data: bytes) -> list[dict]:
    matches: list[dict] = []
    for fs_index, (offset, recorded_size) in enumerate(RECORDED_LANDMARKS, start=1):
        info = parse_romfs(data, offset, recorded_size)
        romfs = data[offset : offset + info.declared_size]
        entries = walk_romfs(romfs, info.root_header_rel, allow_duplicate_headers=True)
        for entry in entries:
            if entry.type_id != 2 or entry.size < min(len(v) for v in SIGNATURES.values()) * 4:
                continue
            payload = entry_bytes(romfs, entry)
            scans = scan_payload(payload)
            for scan in scans:
                if not any(scan["signature_hits"].values()):
                    continue
                candidates = []
                for candidate in scan["candidate_windows"]:
                    enriched = dict(candidate)
                    enriched["start_file_relative"] = candidate["start"]
                    enriched["absolute_firmware_offset"] = offset + entry.data_rel + candidate["start"]
                    enriched["romfs_relative_offset"] = entry.data_rel + candidate["start"]
                    candidates.append(enriched)
                matches.append(
                    {
                        "romfs_index": fs_index,
                        "romfs_offset": offset,
                        "romfs_volume": info.volume_name,
                        "file_path": entry.path,
                        "file_size": entry.size,
                        "file_data_rel": entry.data_rel,
                        "endian": scan["endian"],
                        "signature_hits_file_relative": scan["signature_hits"],
                        "candidate_windows": candidates,
                    }
                )
    return matches


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware", type=Path, help="decompressed M11/M11-P firmware image")
    ap.add_argument("--out", type=Path, required=True, help="derived JSON summary")
    args = ap.parse_args()

    data = args.firmware.read_bytes()
    global_scans = scan_payload(data)
    romfs_matches = scan_romfs(data)

    result = {
        "schema": "m11camera.upstream_color132_probe.v1",
        "scope": "derived_signature_offsets_and_33word_candidates_only",
        "source": {
            "path_name": args.firmware.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "recorded_structure": {
            "size_bytes": STRUCT_BYTES,
            "word_count": STRUCT_WORDS,
            "word_type": "signed_int32",
            "recorded_temperatures_k": list(RECORDED_TEMPERATURES),
            "signatures": {name: list(words) for name, words in SIGNATURES.items()},
        },
        "whole_image_scans": global_scans,
        "romfs_matches": romfs_matches,
        "summary": {
            "romfs_files_with_any_signature": len(romfs_matches),
            "romfs_candidate_window_count": sum(len(x["candidate_windows"]) for x in romfs_matches),
            "romfs_candidates_with_both_recorded_temperatures": sum(
                1
                for x in romfs_matches
                for c in x["candidate_windows"]
                if c["contains_both_recorded_temperatures"]
            ),
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    print(json.dumps(result["summary"], indent=2))
    for match in romfs_matches:
        if match["candidate_windows"]:
            print(
                f"ROMFS{match['romfs_index']} {match['file_path']} endian={match['endian']} "
                f"candidates={len(match['candidate_windows'])}"
            )
            for candidate in match["candidate_windows"][:12]:
                print(
                    "  file_rel={:#x} abs={:#x} sig_words={} temps={} sha256={}".format(
                        candidate["start_file_relative"],
                        candidate["absolute_firmware_offset"],
                        candidate["signature_word_offsets"],
                        candidate["recorded_temperature_word_positions"],
                        candidate["window_sha256"],
                    )
                )


if __name__ == "__main__":
    main()
