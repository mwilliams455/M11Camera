#!/usr/bin/env python3
"""Prove Leica M11-P Category 42 is consumed by the Leica Chroma Suppress selector.

Input is the exact decompressed M11-P 2.6.1 image. Output is derived metadata only.
No proprietary firmware bytes are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
SELECTOR = 0x01579CBC
RELOC_DELTA = 0x40400284


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def s32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def imm16_movwide(word: int) -> int:
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def reg(word: int) -> int:
    return (word >> 12) & 0xF


def require_mov_imm(word: int, rd: int, imm: int) -> None:
    if (word & 0x0FE00000) != 0x03A00000 or reg(word) != rd or (word & 0xFFF) != imm:
        raise ValueError(f"unexpected MOV-immediate word 0x{word:08x}")


def require_movt(word: int, rd: int, imm16: int) -> None:
    if (word & 0x0FF00000) != 0x03400000 or reg(word) != rd or imm16_movwide(word) != imm16:
        raise ValueError(f"unexpected MOVT word 0x{word:08x}")


def unique(data: bytes, needle: bytes) -> int:
    pos = data.find(needle)
    if pos < 0 or data.find(needle, pos + 1) >= 0:
        raise ValueError(f"string is missing or non-unique: {needle!r}")
    return pos


def parse_r2y(data: bytes):
    base = data.find(b"R2YS")
    if base < 0 or data.find(b"R2YS", base + 1) >= 0:
        raise ValueError("R2YS not unique")
    header = data.find(struct.pack("<III", 1, 8, 315), base + 8, base + 0x200)
    if header < 0:
        raise ValueError("R2YS descriptor header missing")
    count = struct.unpack_from("<I", data, header + 8)[0]
    pos = header + 12
    out = []
    for index in range(count):
        flags, descriptor_size, map_size, map_offset, category = struct.unpack_from("<IIIII", data, pos)
        dep_count = (descriptor_size - 20) // 4
        deps = list(struct.unpack_from("<" + "I" * dep_count, data, pos + 20)) if dep_count else []
        out.append(
            {
                "index": index,
                "flags": flags,
                "descriptor_size": descriptor_size,
                "map_size": map_size,
                "map_offset_rel": map_offset,
                "category": category,
                "dependencies_s32": [s32(x) for x in deps],
            }
        )
        pos += descriptor_size
    return base, out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(digest)

    base, descriptors = parse_r2y(data)
    cat42 = [x for x in descriptors if x["category"] == 42]
    if len(cat42) != 8:
        raise ValueError(f"Category 42 count {len(cat42)}")
    if any(x["map_size"] != 44 or x["flags"] != 0x206 for x in cat42):
        raise ValueError("Category 42 shape/flags mismatch")
    states = sorted(x["dependencies_s32"][2] for x in cat42)
    if states != [-3, -2, -1, 0, 1, 2, 3, 10]:
        raise ValueError(states)
    if any(x["dependencies_s32"][:2] != [0, 200000] for x in cat42):
        raise ValueError("Category 42 ISO dependency mismatch")

    # Exact A32 selector anchors from the genuine image.
    require_mov_imm(u32(data, 0x01579E14), 0, 42)
    require_mov_imm(u32(data, 0x01579E34), 0, 42)
    require_mov_imm(u32(data, 0x01579E30), 3, 29)
    require_movt(u32(data, 0x01579E38), 3, 0xBB06)
    require_mov_imm(u32(data, 0x01579E58), 2, 28)
    require_movt(u32(data, 0x01579E60), 2, 0xBB06)
    command_wait = 0xBB06001D
    command_send = 0xBB06001C

    dep = unique(data, b"Dependency.Iso:%d   Saturation:%d")
    err = unique(data, b"----ERROR-----   img_macro_drv_r2y_select_chroma_suppress_paraset 1")
    no_valid = unique(
        data,
        b"NO VALID STRING ->  E_IMG_MACRO_DRV_R2Y_CATEGORY_CsCo_R2Y6A  img_macro_drv_r2y_select_chroma_suppress_paraset",
    )
    loaded = unique(data, b"(r2y) R2Y CHROMA SUPPRESS already loaded")

    # Selector loads two runtime log pointers. Their exact common relocation maps
    # them back into the unique Chroma Suppress string cluster above.
    require_movt(u32(data, 0x01579DC8), 1, 0x42B8)
    if imm16_movwide(u32(data, 0x01579DC0)) != 0x9210:
        raise ValueError("dependency log low half mismatch")
    require_movt(u32(data, 0x01579F9C), 1, 0x42B8)
    if imm16_movwide(u32(data, 0x01579F94)) != 0x9234:
        raise ValueError("error log low half mismatch")
    dep_runtime = 0x42B89210
    err_runtime = 0x42B89234
    if dep_runtime - dep != RELOC_DELTA or err_runtime - err != RELOC_DELTA:
        raise ValueError("selector string relocation mismatch")

    lines = [
        "# M11-P Category 42 Leica Chroma Suppress consumer proof",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- R2YS base: `0x{base:08x}`",
        "- Category 42 descriptor count: `8`",
        "- Category 42 flags: `0x206` for all eight maps",
        "- Category 42 map size: `44 bytes` for all eight maps",
        f"- Category 42 saturation states: `{states}`",
        "- Category 42 dependencies: ISO `0..200000` plus Saturation state",
        "",
        "## Direct Leica selector evidence",
        "",
        f"- selector function: `0x{SELECTOR:08x}`",
        "- `0x01579e14`: exact A32 `MOV r0,#42` before selector-side category handling.",
        "- `0x01579e34`: exact A32 `MOV r0,#42` in the command/wait path.",
        f"- that path constructs command `0x{command_wait:08x}`.",
        f"- the send path constructs command `0x{command_send:08x}` and sends a 16-byte control packet.",
        f"- selector dependency log runtime `0x{dep_runtime:08x}` -> file `0x{dep:08x}` using relocation `0x{RELOC_DELTA:08x}`.",
        f"- selector error log runtime `0x{err_runtime:08x}` -> file `0x{err:08x}` using the same relocation.",
        f"- unique selector identity string cluster starts at `0x{loaded:08x}` / `0x{no_valid:08x}` and explicitly names `E_IMG_MACRO_DRV_R2Y_CATEGORY_CsCo_R2Y6A` and `img_macro_drv_r2y_select_chroma_suppress_paraset`.",
        "",
        "## Decision",
        "",
        "**PRIMARY M11 CONSUMER EVIDENCE:** R2YS Category 42 is selected by Leica's `img_macro_drv_r2y_select_chroma_suppress_paraset` / `CsCo` path. The prior Category-42 -> Chroma Suppress identification is no longer merely structural inference.",
        "",
        "The separate low-level Milbeaut receiver call into `Im_R2Y_Ctrl_Chroma_Suppress` remains a downstream trace target. This proof does not establish exact CSP arithmetic, clamp placement, or which values are active in each highlight regime. The renderer must remain frozen until those semantics are established.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines))
    print(args.output)


if __name__ == "__main__":
    main()
