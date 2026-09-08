#!/usr/bin/env python3
"""Reproduce canonical Leica M11-P 2.6.1 colour-pipeline forensic assets.

The firmware binary is proprietary and is never stored in the repository. This
extractor operates on a locally supplied official updater, verifies the packed
body MD5 and the known unpacked-image SHA-256, parses the embedded R2YS database,
and emits only derived tables/metadata needed by the reference renderer.

Primary reproduced assets:
- Category 3 CC0 Q9 matrix
- Category 13 CC1 Q9 ISO bands
- Category 5 tone configuration and Category 6 7x1024 Q12 tone curves
- Category 15 fine gamma nibbles + Category 20 256-node coarse gamma table
- Category 24 RGB->Y/Cb/Cr-like matrix
- Category 42 saturation-dependent parameter family
- upstream 132-byte sro.bin colour-management core
- complete 315-descriptor R2Y inventory
- provenance manifest with source/region/output hashes
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import struct
from pathlib import Path

EXPECTED_UNPACKED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
ROMFS = ((0x00E3A160, 3_629_024), (0x0333DF70, 43_912_464))
EXPECTED_TONE_RANGES = {
    -3: (4096, 4096),
    -2: (3004, 4348),
    -1: (2185, 4602),
    0: (1911, 4867),
    1: (1365, 5290),
    2: (1057, 5742),
    3: (793, 6225),
}
EXPECTED_CC0 = [[495, -58, 63], [10, 601, -111], [49, -255, 705]]
EXPECTED_CC1_LOW = [[1041, -372, -157], [-117, 630, -1], [-4, -78, 595]]
EXPECTED_YCC = [[77, 150, 29], [-43, -85, 128], [128, -107, -21]]
EXPECTED_SAT = {-3: 357, -2: 434, -1: 511, 0: 588, 1: 665, 2: 741, 3: 818}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def s32(value: int) -> int:
    return value - 2**32 if value >= 2**31 else value


def read_base128_uint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    groups = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated base-128 integer")
        byte = buf[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        groups += 1
        if groups > 5:
            raise ValueError("base-128 integer is implausibly long")
        if not (byte & 0x80):
            return value, pos


def decompress(fw: bytes) -> tuple[bytes, dict]:
    if len(fw) < 0x28:
        raise ValueError("firmware is too small")
    body_off = struct.unpack_from("<I", fw, 4)[0]
    unpacked_size = struct.unpack_from("<I", fw, 0x0C)[0]
    packed_size = struct.unpack_from("<I", fw, 0x14)[0]
    md5_expected = fw[0x18:0x28]
    if body_off + packed_size > len(fw):
        raise ValueError("packed body lies outside firmware")
    body = fw[body_off : body_off + packed_size]
    md5_actual = hashlib.md5(body).digest()
    if md5_actual != md5_expected:
        raise ValueError("packed MD5 mismatch")

    marker = body[0]
    out = bytearray()
    pos = 1
    while pos < len(body):
        byte = body[pos]
        if byte != marker:
            out.append(byte)
            pos += 1
            continue
        if pos + 1 >= len(body):
            raise ValueError("truncated marker")
        if body[pos + 1] == 0:
            out.append(marker)
            pos += 2
            continue
        length, next_pos = read_base128_uint(body, pos + 1)
        distance, next_pos = read_base128_uint(body, next_pos)
        if distance <= 0 or distance > len(out):
            raise ValueError(f"bad backref distance {distance}")
        for _ in range(length):
            out.append(out[-distance])
        pos = next_pos

    if len(out) != unpacked_size:
        raise ValueError(f"unpacked size mismatch {len(out)} != {unpacked_size}")
    return bytes(out), {
        "body_offset": body_off,
        "packed_size": packed_size,
        "unpacked_size": unpacked_size,
        "marker": marker,
        "packed_md5_expected": md5_expected.hex(),
        "packed_md5_actual": md5_actual.hex(),
    }


def parse_r2y(data: bytes) -> tuple[int, int, int, list[dict]]:
    base = data.find(b"R2YS")
    if base < 0 or data.find(b"R2YS", base + 1) >= 0:
        raise ValueError("R2YS marker is missing or not unique")
    size = struct.unpack_from("<I", data, base + 4)[0]
    if data[base + size - 4 : base + size] != b"R2YE":
        raise ValueError("R2YE end marker mismatch")

    header_pattern = struct.pack("<III", 1, 8, 315)
    header_abs = data.find(header_pattern, base + 8, base + 0x200)
    if header_abs < 0:
        raise ValueError("R2Y database header not found")
    db_header_rel = header_abs - base
    _, _, count = struct.unpack_from("<III", data, header_abs)

    pos = header_abs + 12
    descriptors: list[dict] = []
    for index in range(count):
        flags, descriptor_size, map_size, map_offset_rel, category = struct.unpack_from(
            "<IIIII", data, pos
        )
        if descriptor_size < 20 or descriptor_size % 4:
            raise ValueError(f"invalid descriptor size {descriptor_size} at index {index}")
        dep_count = (descriptor_size - 20) // 4
        deps = list(struct.unpack_from("<" + "I" * dep_count, data, pos + 20)) if dep_count else []
        descriptors.append(
            {
                "index": index,
                "descriptor_rel": pos - base,
                "flags": flags,
                "flags_hex": f"0x{flags:x}",
                "descriptor_size": descriptor_size,
                "map_size": map_size,
                "map_offset_rel": map_offset_rel,
                "map_offset_abs": base + map_offset_rel,
                "category": category,
                "dependencies_u32": deps,
                "dependencies_s32": [s32(x) for x in deps],
            }
        )
        pos += descriptor_size

    if pos - base != min(x["map_offset_rel"] for x in descriptors):
        raise ValueError("descriptor table does not terminate at the map region")
    return base, size, db_header_rel, descriptors


def map_bytes(data: bytes, base: int, descriptor: dict) -> bytes:
    start = base + descriptor["map_offset_rel"]
    return data[start : start + descriptor["map_size"]]


def matrix3(values) -> list[list[int]]:
    values = list(values)
    return [values[0:3], values[3:6], values[6:9]]


def gamma_reconstruct(coarse, payload: bytes, high_first: bool) -> tuple[list[int], int, float]:
    output: list[int] = []
    for group in range(256):
        value = coarse[group]
        for byte in payload[group * 8 : (group + 1) * 8]:
            nibbles = ((byte >> 4, byte & 0xF) if high_first else (byte & 0xF, byte >> 4))
            for increment in nibbles:
                output.append(value)
                value += increment
    second = [output[i + 2] - 2 * output[i + 1] + output[i] for i in range(len(output) - 2)]
    roughness = sum(abs(x) for x in second)
    rms = math.sqrt(sum(x * x for x in second) / len(second))
    return output, roughness, rms


def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware", type=Path, help="local official Leica M11-P 2.6.1 .FW")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    fw = args.firmware.read_bytes()
    firmware_sha = sha(fw)
    unpacked, header = decompress(fw)
    unpacked_sha = sha(unpacked)
    if unpacked_sha != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {unpacked_sha}")

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    base, r2y_size, db_header_rel, descriptors = parse_r2y(unpacked)
    r2y = unpacked[base : base + r2y_size]
    by_category: dict[int, list[dict]] = {}
    for descriptor in descriptors:
        by_category.setdefault(descriptor["category"], []).append(descriptor)

    # Category 3: CC0.
    descriptor = by_category[3][0]
    raw = map_bytes(unpacked, base, descriptor)
    values = struct.unpack("<21h", raw)
    cc0 = matrix3(values[1:10])
    if cc0 != EXPECTED_CC0:
        raise ValueError(f"CC0 mismatch: {cc0}")
    write_json(
        out / "category3_CC0_candidate.json",
        {
            "schema": "m11camera.forensics.category3_cc0.v1",
            "source": descriptor,
            "map_sha256": sha(raw),
            "raw_i16": list(values),
            "matrix_q9": cc0,
            "q_denominator": 512,
            "matrix_byte_offset_within_map": 2,
            "map_tail_i16": list(values[10:]),
        },
    )

    # Category 13: full CC1 ISO family.
    bands = []
    for descriptor in by_category[13]:
        raw = map_bytes(unpacked, base, descriptor)
        values = struct.unpack("<16h", raw)
        bands.append(
            {
                "descriptor": descriptor,
                "map_sha256": sha(raw),
                "raw_i16": list(values),
                "matrix_q9": matrix3(values[1:10]),
                "q_denominator": 512,
                "iso_range": descriptor["dependencies_u32"],
                "tail_i16": list(values[10:]),
            }
        )
    if bands[0]["matrix_q9"] != EXPECTED_CC1_LOW:
        raise ValueError("low-ISO CC1 mismatch")
    write_json(out / "category13_CC1_candidate.json", {"schema": "m11camera.forensics.category13_cc1.v1", "bands": bands})

    # Category 5 tone configuration and Category 6 seven 1024-entry Q12 curves.
    tone_config_desc = by_category[5][0]
    tone_config_raw = map_bytes(unpacked, base, tone_config_desc)
    tone_config = struct.unpack("<29h", tone_config_raw)
    luma_weights = list(tone_config[8:11])
    q12_unity = tone_config[11]
    if luma_weights != [77, 149, 29] or q12_unity != 4096:
        raise ValueError("tone configuration mismatch")

    curves = {}
    curve_meta = []
    for descriptor in by_category[6]:
        state = descriptor["dependencies_s32"][0]
        raw = map_bytes(unpacked, base, descriptor)
        values = struct.unpack("<1024H", raw)
        observed_range = (min(values), max(values))
        if observed_range != EXPECTED_TONE_RANGES[state]:
            raise ValueError(f"tone range mismatch for state {state}: {observed_range}")
        curves[state] = values
        curve_meta.append(
            {
                "state": state,
                "descriptor": descriptor,
                "map_sha256": sha(raw),
                "min": observed_range[0],
                "max": observed_range[1],
            }
        )

    tone_csv = out / "tone_q12_reconstructed_curves.csv"
    with tone_csv.open("w", newline="") as file:
        fields = ["index", "input_norm"] + [f"gain_q12_{state:+d}" for state in range(-3, 4)]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for index in range(1024):
            row = {"index": index, "input_norm": index / 1023}
            for state in range(-3, 4):
                row[f"gain_q12_{state:+d}"] = curves[state][index]
            writer.writerow(row)
    write_json(
        out / "tone_q12_metadata.json",
        {
            "schema": "m11camera.forensics.tone_q12.v1",
            "config_descriptor": tone_config_desc,
            "config_map_sha256": sha(tone_config_raw),
            "config_raw_i16": list(tone_config),
            "luma_weights": luma_weights,
            "luma_weight_denominator": 255,
            "q12_unity": q12_unity,
            "curve_maps": curve_meta,
            "csv": tone_csv.name,
            "csv_sha256": sha(tone_csv.read_bytes()),
        },
    )

    # Gamma: Category 15 fine nibble payload + Category 20 coarse 10-bit nodes.
    fine_desc = by_category[15][0]
    coarse_desc = by_category[20][0]
    fine = map_bytes(unpacked, base, fine_desc)
    coarse_raw = map_bytes(unpacked, base, coarse_desc)
    coarse = struct.unpack("<256H", coarse_raw)
    high, high_l1, high_rms = gamma_reconstruct(coarse, fine, True)
    low, low_l1, low_rms = gamma_reconstruct(coarse, fine, False)
    if high_l1 != 1179 or low_l1 != 1302:
        raise ValueError("gamma roughness metrics mismatch")
    if abs(high_rms - 0.5957429175741542) > 1e-12 or abs(low_rms - 0.6153071049604038) > 1e-12:
        raise ValueError("gamma RMS metrics mismatch")

    gamma_csv = out / "gamma_4096_high_nibble_first.csv"
    with gamma_csv.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["index", "input_norm", "output_10bit", "output_norm"])
        writer.writeheader()
        for index, value in enumerate(high):
            writer.writerow(
                {
                    "index": index,
                    "input_norm": index / 4095,
                    "output_10bit": value,
                    "output_norm": value / 1023,
                }
            )
    high_u16 = struct.pack("<4096H", *high)
    low_u16 = struct.pack("<4096H", *low)
    write_json(
        out / "gamma_metadata.json",
        {
            "schema": "m11camera.forensics.gamma.v1",
            "coarse_descriptor": coarse_desc,
            "coarse_sha256": sha(coarse_raw),
            "coarse_nodes": list(coarse),
            "fine_descriptor": fine_desc,
            "fine_sha256": sha(fine),
            "fine_payload_bytes": len(fine),
            "reconstruction": "for each of 256 groups: accumulator=coarse[group]; decode 16 nibbles from 8 bytes; append accumulator before adding each nibble; selected nibble order high then low",
            "high_nibble_first": {
                "second_difference_l1": high_l1,
                "second_difference_rms": high_rms,
                "u16le_sha256": sha(high_u16),
                "csv": gamma_csv.name,
                "csv_sha256": sha(gamma_csv.read_bytes()),
            },
            "low_nibble_first": {
                "second_difference_l1": low_l1,
                "second_difference_rms": low_rms,
                "u16le_sha256": sha(low_u16),
            },
        },
    )

    # Category 24: RGB -> Y/Cb/Cr-like matrix.
    descriptor = by_category[24][0]
    raw = map_bytes(unpacked, base, descriptor)
    values = struct.unpack("<9h", raw)
    ycc = matrix3(values)
    if ycc != EXPECTED_YCC:
        raise ValueError("Category-24 YCC matrix mismatch")
    write_json(
        out / "category24_YCC.json",
        {
            "schema": "m11camera.forensics.category24_ycc.v1",
            "descriptor": descriptor,
            "map_sha256": sha(raw),
            "matrix": ycc,
            "denominator": 256,
        },
    )

    # Category 42: saturation-dependent 44-byte parameter family.
    saturation_states = []
    for descriptor in by_category[42]:
        state = descriptor["dependencies_s32"][2]
        raw = map_bytes(unpacked, base, descriptor)
        values = struct.unpack("<22h", raw)
        saturation_states.append(
            {
                "state": state,
                "descriptor": descriptor,
                "map_sha256": sha(raw),
                "raw_i16": list(values),
                "raw_map_offset_plus_8": values[4],
                "raw_map_offset_plus_10": values[5],
                "payload_after_leading_word_offset_plus_6": values[4],
                "payload_after_leading_word_offset_plus_8": values[5],
            }
        )
        if state in EXPECTED_SAT and (values[4] != EXPECTED_SAT[state] or values[5] != EXPECTED_SAT[state]):
            raise ValueError(f"Category-42 saturation mismatch for state {state}")
        if state == 10 and (values[4] != 0 or values[5] != 0):
            raise ValueError("Category-42 monochrome sentinel mismatch")
    write_json(
        out / "category42_saturation.json",
        {
            "schema": "m11camera.forensics.category42_saturation.v1",
            "note": "Historical +6/+8 offsets are relative to the payload after the leading 2-byte word; absolute raw-map offsets are +8/+10. Other fields also vary by saturation state, so this family is not an exact single-scalar chroma model.",
            "states": saturation_states,
        },
    )

    # Upstream sro.bin 132-byte colour-management core.
    needle = b"img/data/sro.bin\x00"
    hits = []
    pos = 0
    while True:
        hit = unpacked.find(needle, pos)
        if hit < 0:
            break
        hits.append(hit)
        pos = hit + 1
    sro_path = next(
        (hit for hit in hits if unpacked[hit + len(needle) : hit + len(needle) + 7] == b"\x55" * 7),
        -1,
    )
    if sro_path < 0:
        raise ValueError(f"default sro.bin block missing among hits {hits}")
    after_path = sro_path + len(needle)
    leading_fill = unpacked[after_path : after_path + 7]
    core_offset = after_path + 7
    core = unpacked[core_offset : core_offset + 132]
    trailing_fill = unpacked[core_offset + 132 : core_offset + 136]
    if leading_fill != b"\x55" * 7 or trailing_fill != b"\x55" * 4:
        raise ValueError("SRO fill/sentinel mismatch")
    words = struct.unpack("<33i", core)
    write_json(
        out / "sro_colour_management.json",
        {
            "schema": "m11camera.forensics.sro_colour_management.v1",
            "path_string_offset_abs": sro_path,
            "after_path_offset_abs": after_path,
            "leading_fill_55_bytes": 7,
            "core_offset_abs": core_offset,
            "core_size": 132,
            "core_sha256": sha(core),
            "core_words_i32": list(words),
            "cm1_q12": matrix3(words[0:9]),
            "cm1_metadata": [words[9], words[10]],
            "cm2_q12": matrix3(words[11:20]),
            "cm2_metadata": [words[20], words[21]],
            "internal_matrix_raw": matrix3(words[22:31]),
            "internal_metadata": [words[31], words[32]],
            "trailing_fill_55_bytes": 4,
            "envelope_after_path_size": 143,
            "envelope_after_path_sha256": sha(unpacked[after_path : core_offset + 136]),
        },
    )

    # Full descriptor inventory and provenance.
    write_json(
        out / "r2y_descriptor_inventory.json",
        {
            "schema": "m11camera.forensics.r2y_descriptor_inventory.v1",
            "r2ys_offset_abs": base,
            "r2ys_size": r2y_size,
            "r2ys_sha256": sha(r2y),
            "database_header_rel": db_header_rel,
            "version": 1,
            "header_second_word": 8,
            "descriptor_count": len(descriptors),
            "descriptors": descriptors,
        },
    )

    romfs = []
    for offset, expected_size in ROMFS:
        if unpacked[offset : offset + 8] != b"-rom1fs-":
            raise ValueError(f"ROMFS magic missing at {offset:#x}")
        declared = struct.unpack_from(">I", unpacked, offset + 8)[0]
        if declared != expected_size:
            raise ValueError(f"ROMFS size mismatch at {offset:#x}")
        romfs.append({"offset_abs": offset, "size": declared, "sha256": sha(unpacked[offset : offset + declared])})

    outputs = {}
    for path in sorted(out.iterdir()):
        if path.name != "manifest.json" and path.is_file():
            outputs[path.name] = {"size": path.stat().st_size, "sha256": sha(path.read_bytes())}

    write_json(
        out / "manifest.json",
        {
            "schema": "m11camera.forensics.manifest.v1",
            "source_firmware": {"name": args.firmware.name, "size": len(fw), "sha256": firmware_sha, **header},
            "unpacked": {"size": len(unpacked), "sha256": unpacked_sha},
            "romfs": romfs,
            "r2ys": {
                "offset_abs": base,
                "size": r2y_size,
                "sha256": sha(r2y),
                "end_marker_offset_abs": base + r2y_size - 4,
            },
            "sro": {
                "path_string_offset_abs": sro_path,
                "core_offset_abs": core_offset,
                "core_size": 132,
                "leading_fill_55_bytes": 7,
                "trailing_fill_55_bytes": 4,
            },
            "canonical_gates": {
                "cc0_match": True,
                "cc1_low_iso_match": True,
                "tone_ranges_match": True,
                "gamma_metrics_match": True,
                "category24_ycc_match": True,
                "category42_states_match": True,
            },
            "outputs": outputs,
        },
    )

    print(
        json.dumps(
            {
                "firmware_sha256": firmware_sha,
                "unpacked_sha256": unpacked_sha,
                "r2ys_offset": hex(base),
                "r2ys_size": r2y_size,
                "descriptor_count": len(descriptors),
                "gamma_high_nibble_second_difference_l1": high_l1,
                "gamma_high_nibble_second_difference_rms": high_rms,
                "tone_standard_map_sha256": next(x["map_sha256"] for x in curve_meta if x["state"] == 0),
                "outputs": len(outputs),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
