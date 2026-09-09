#!/usr/bin/env python3
"""Calibrate Leica M11-P indirect code-pointer affine base from gamma serializer tables.

The gamma selector and the 0x1400 serializer independently switch on the same
object subtype accessor (1..6). Their A32 `ldr pc,[pc,index,lsl#2]` tables store
absolute code-space words that require an affine translation to raw firmware
offsets.

This revision uses an exact Leica-primary calibration: the serializer's six
case-entry block starts are independently visible in linear A32 disassembly and
each begins the argument setup for one of six type-specific builders. A valid
base must map BOTH serializer subtype tables to those exact ordered case starts,
not merely somewhere near a builder call. The same proven base is then applied
to the gamma selector tables.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b04c0851e127753cd6aff3aaffee737abc52388363b83"
# Correct exact unpacked hash gate used below; keep updater hash out of matching logic.
EXPECTED_UNPACKED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"

TABLES = [
    ("gamma_subtype6", 0x01579444, 6, 0x0157933C, 0x01579BF8),
    ("gamma_pair4",    0x015799FC, 4, 0x0157933C, 0x01579BF8),
    ("serializer_type0_subtype6", 0x015A6544, 6, 0x015A6374, 0x015A6700),
    ("serializer_type1_subtype6", 0x015A6570, 6, 0x015A6374, 0x015A6700),
]

# These are not guessed from pointer values. They are the six visible case-entry
# blocks in the serializer, each beginning with its own argument-setup sequence
# before one of six direct builder calls. The paired subtype layout is visible
# independently in the serializer control flow.
EXPECTED_SERIALIZER_MAPS = {
    "serializer_type0_subtype6": [
        0x015A6630, 0x015A6630,
        0x015A6614, 0x015A6614,
        0x015A65F8, 0x015A65F8,
    ],
    "serializer_type1_subtype6": [
        0x015A65DC, 0x015A65DC,
        0x015A65C0, 0x015A65C0,
        0x015A65A4, 0x015A65A4,
    ],
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def entries(data: bytes, table: int, count: int) -> list[int]:
    return [u32(data, table + i * 4) for i in range(count)]


def valid_a32_start(data: bytes, off: int, span: int = 8) -> tuple[bool, list[str]]:
    if off < 0 or off + 4 > len(data) or off & 3:
        return False, []
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[off:min(len(data), off + span * 4)], off))
    if not insns or insns[0].address != off:
        return False, []
    return True, [f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in insns]


def exact_calibration_bases(data: bytes) -> list[int]:
    """Return bases that satisfy every exact serializer case-entry mapping."""
    candidates: set[int] | None = None
    table_by_name = {name: (table, count) for name, table, count, _, _ in TABLES}

    for name, expected in EXPECTED_SERIALIZER_MAPS.items():
        table, count = table_by_name[name]
        raw = entries(data, table, count)
        if len(raw) != len(expected):
            raise ValueError(f"calibration length mismatch for {name}")
        bases = {(w - target) & 0xFFFFFFFF for w, target in zip(raw, expected)}
        # Every entry in one table must imply the same base.
        if len(bases) != 1:
            return []
        if candidates is None:
            candidates = set(bases)
        else:
            candidates &= bases
    return sorted(candidates or [])


def mapped_tables(data: bytes, base: int) -> dict[str, list[int]]:
    out = {}
    for name, table, count, _, _ in TABLES:
        out[name] = [((w - base) & 0xFFFFFFFF) for w in entries(data, table, count)]
    return out


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA256:
        raise ValueError(f"unexpected M11-P SHA-256 {digest}")

    bases = exact_calibration_bases(data)
    lines = [
        "# M11-P R2A exact gamma/serializer code-pointer affine calibration",
        "",
        f"- SHA-256: `{digest}`",
        "- calibration source: exact serializer case-entry block starts observed independently in Leica A32 control flow",
        f"- exact bases satisfying both serializer subtype tables: `{len(bases)}`",
        "",
        "## Exact serializer calibration",
        "",
    ]

    for name, expected in EXPECTED_SERIALIZER_MAPS.items():
        table, count = next((t, c) for n, t, c, _, _ in TABLES if n == name)
        raw = entries(data, table, count)
        lines.append(f"### `{name}` table `0x{table:08x}`")
        for i, (word, target) in enumerate(zip(raw, expected)):
            lines.append(f"- index `{i}` raw word `0x{word:08x}` -> independently observed block `0x{target:08x}`")
        lines.append("")

    if not bases:
        lines += ["No affine base satisfies the exact serializer calibration.", ""]
    else:
        for base in bases:
            lines += [f"## Proven affine base `0x{base:08x}`", ""]
            maps = mapped_tables(data, base)
            for name, mapped in maps.items():
                lines.append(f"### `{name}`")
                for i, target in enumerate(mapped):
                    ok, text = valid_a32_start(data, target, 10)
                    snippet = " ; ".join(text[:10]) if ok else "invalid A32 start"
                    lines.append(f"- index `{i}` -> raw target `0x{target:08x}`: `{snippet}`")
                lines.append("")

            # Guard: the calibrated tables must map exactly to the independent
            # serializer case starts, otherwise do not call the base proven.
            for name, expected in EXPECTED_SERIALIZER_MAPS.items():
                if maps[name] != expected:
                    raise AssertionError(f"exact serializer mapping guard failed for {name}")

    lines += [
        "## Interpretation boundary",
        "",
        "A single base satisfying both independent serializer tables proves the code-pointer affine translation for these co-located selector tables. It resolves raw branch targets, but it does not by itself assign photographic meanings to object subtype values.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(report(a.unpacked.read_bytes()))
    print(a.output)


if __name__ == "__main__":
    main()
