#!/usr/bin/env python3
"""Trace the M11-P still-output boundary after R2Y.

Goal: determine whether the Leica still path hands R2Y Y/Cb/Cr output directly to
later still/JPEG stages, and locate any intervening RGB/output-transfer stage.

This is a locator/consumer trace only. It does not change renderer behaviour and
does not infer a transfer function from photographs.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

# Closed still-path anchor from earlier B2R/R2Y provenance work.
STILL_B2B_R2Y_JOB = 0x017B9BCC
# Project-established data/string pointer affine used by Leica ARM code.
DATA_AFFINE = 0x3FAA87D0

KEYWORDS = (
    "jpeg", "jpg", "stillencoder", "still encoder", "encoder_still",
    "fj_encoder_still", "ycc", "ycbcr", "yyw", "r2y", "chroma",
    "encode", "jfif", "exif", "b2b_r2y", "img_wfq_job_b2b_r2y",
)


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    # ARM-state BL immediate only. BLX and Thumb are intentionally excluded.
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (off + 8 + (imm << 2)) & 0xFFFFFFFF


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    return md


def ascii_strings(data: bytes, min_len: int = 5):
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in rx.finditer(data):
        yield m.start(), m.group().decode("ascii", "replace")


def nearest_prologue(md: Cs, data: bytes, target: int, window: int = 0x12000) -> int | None:
    best = None
    lo = max(0, target - window) & ~3
    for off in range(lo, min(target + 1, len(data) - 3), 4):
        ins = list(md.disasm(data[off:off + 4], off, count=1))
        if not ins:
            continue
        x = ins[0]
        s = x.op_str.lower()
        if (x.mnemonic == "push" and "lr" in s) or (
            x.mnemonic.startswith("stm") and "sp!" in s and "lr" in s
        ):
            best = off
    return best


def function(md: Cs, data: bytes, entry: int, max_len: int = 0x10000):
    out = []
    for x in md.disasm(data[entry:min(len(data), entry + max_len)], entry):
        out.append(x)
        if x.address > entry + 8:
            s = (x.mnemonic + " " + x.op_str).lower()
            if (x.mnemonic == "pop" and "pc" in x.op_str.lower()) or s.startswith("bx lr") or (
                x.mnemonic.startswith("ldm") and "pc" in x.op_str.lower()
            ):
                break
    return out


def direct_callers(data: bytes, target: int, cap: int = 200) -> list[int]:
    out = []
    for off in range(0, len(data) - 3, 4):
        if bl_target(off, u32(data, off)) == target:
            out.append(off)
            if len(out) >= cap:
                break
    return out


def fmt(x) -> str:
    return f"0x{x.address:08X}: {x.mnemonic} {x.op_str}".rstrip()


def function_calls(data: bytes, insns) -> list[tuple[int, int]]:
    out = []
    for x in insns:
        if x.address + 4 > len(data):
            continue
        target = bl_target(x.address, u32(data, x.address))
        if target is not None:
            out.append((x.address, target))
    return out


def movw_movt_constants(insns):
    """Yield (address, register, value) for nearby MOVW/MOVT pairs."""
    for idx, x in enumerate(insns):
        if x.mnemonic != "movw" or "#" not in x.op_str:
            continue
        reg = x.op_str.split(",", 1)[0].strip()
        try:
            lo = int(x.op_str.split("#", 1)[1], 0) & 0xFFFF
        except ValueError:
            continue
        for y in insns[idx + 1:idx + 8]:
            if y.mnemonic == "movt" and y.op_str.startswith(reg + ",") and "#" in y.op_str:
                try:
                    hi = int(y.op_str.split("#", 1)[1], 0) & 0xFFFF
                except ValueError:
                    break
                yield x.address, reg, (hi << 16) | lo
                break


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    md = disassembler()

    # Semantic strings are evidence locators, not behavioural proof.
    strings = []
    raw_by_off: dict[int, str] = {}
    for off, text in ascii_strings(data):
        low = text.lower()
        matched = sorted({k for k in KEYWORDS if k in low})
        if matched:
            row = {"offset": off, "text": text[:500], "keywords": matched}
            strings.append(row)
            raw_by_off[off] = text

    wanted_raw = set(raw_by_off)
    wanted_runtime = {((off + DATA_AFFINE) & 0xFFFFFFFF): off for off in wanted_raw}

    # Literal-pool pointer references.
    literal_refs: dict[int, list[int]] = defaultdict(list)
    for p in range(0, len(data) - 3, 4):
        word = u32(data, p)
        raw = None
        if word in wanted_raw:
            raw = word
        elif word in wanted_runtime:
            raw = wanted_runtime[word]
        if raw is not None and len(literal_refs[raw]) < 100:
            literal_refs[raw].append(p)

    # MOVW/MOVT constructed string pointers: scan code region broadly but only
    # retain constants that resolve to our keyword strings.
    constructed_refs: dict[int, list[int]] = defaultdict(list)
    # The known executable functions used by this project are below 0x03000000.
    # Restricting the disassembly avoids interpreting large data/ROMFS regions.
    code_hi = min(len(data), 0x03000000)
    code_insns = list(md.disasm(data[:code_hi], 0))
    for at, _reg, value in movw_movt_constants(code_insns):
        raw = None
        if value in wanted_raw:
            raw = value
        elif value in wanted_runtime:
            raw = wanted_runtime[value]
        if raw is not None and len(constructed_refs[raw]) < 100:
            constructed_refs[raw].append(at)

    # Associate string refs with nearest function prologues, then look for
    # functions that contain both R2Y/YCC semantics and still/JPEG semantics.
    function_rows: dict[int, dict] = {}
    for row in strings:
        refs = sorted(set(literal_refs.get(row["offset"], []) + constructed_refs.get(row["offset"], [])))
        row["refs"] = refs
        for ref in refs:
            entry = nearest_prologue(md, data, ref)
            if entry is None:
                continue
            f = function_rows.setdefault(entry, {"strings": [], "refs": []})
            f["strings"].append(row)
            f["refs"].append(ref)

    def bucket(row: dict) -> set[str]:
        ks = set(row["keywords"])
        out = set()
        if ks & {"r2y", "ycc", "ycbcr", "yyw", "chroma", "b2b_r2y", "img_wfq_job_b2b_r2y"}:
            out.add("R2Y/YCC")
        if ks & {"jpeg", "jpg", "stillencoder", "still encoder", "encoder_still", "fj_encoder_still", "encode", "jfif"}:
            out.add("JPEG/STILL")
        if "exif" in ks:
            out.add("EXIF")
        return out

    mixed = []
    for entry, info in function_rows.items():
        buckets = set()
        for row in info["strings"]:
            buckets |= bucket(row)
        if "R2Y/YCC" in buckets and "JPEG/STILL" in buckets:
            mixed.append((entry, info, buckets))

    # Closed still B2R/R2Y job and its direct callers.
    job_entry = STILL_B2B_R2Y_JOB
    job_ins = function(md, data, job_entry)
    job_calls = function_calls(data, job_ins)
    job_callers = direct_callers(data, job_entry)

    parent_rows = []
    for callsite in job_callers:
        entry = nearest_prologue(md, data, callsite)
        if entry is None:
            continue
        ins = function(md, data, entry)
        parent_rows.append((entry, callsite, ins, function_calls(data, ins)))

    lines = [
        "# M11-P still R2Y → output/JPEG boundary trace",
        "",
        f"- canonical unpacked SHA-256: `{digest}`",
        f"- known still B2B/R2Y job: `0x{STILL_B2B_R2Y_JOB:08X}`",
        f"- data/string affine: `0x{DATA_AFFINE:08X}`",
        f"- keyword-bearing ASCII strings: `{len(strings)}`",
        f"- functions with both R2Y/YCC and JPEG/still string evidence: `{len(mixed)}`",
        "",
        "## Public-driver architectural constraint used for interpretation",
        "",
        "The Socionext/Milbeaut R2Y public API exposes YYW output as Y/Cb/Cr planes and explicit YCC444/YCC422/YCC420 thinning. It also exposes 8/10-bit YCbCr format selection and 8/10/12/16-bit write packing. Therefore an RGB inverse/output OETF after R2Y must not be invented unless Leica code shows one before the still encoder.",
        "",
        "## Known still B2B/R2Y job direct calls",
        "",
        "```asm",
    ]
    for x in job_ins:
        target = bl_target(x.address, u32(data, x.address)) if x.address + 4 <= len(data) else None
        suffix = f" ; BL=0x{target:08X}" if target is not None else ""
        lines.append(fmt(x) + suffix)
    lines += ["```", "", f"Direct callers: `{[hex(x) for x in job_callers]}`", ""]

    for entry, callsite, ins, calls in parent_rows:
        lines += [
            f"## Parent `0x{entry:08X}` via callsite `0x{callsite:08X}`",
            "",
            "### Direct BL targets",
            "",
        ]
        for at, target in calls:
            lines.append(f"- `0x{at:08X}` → `0x{target:08X}`")
        lines += ["", "### Function disassembly", "", "```asm"]
        lines += [fmt(x) for x in ins]
        lines += ["```", ""]

    lines += ["## Mixed semantic functions", ""]
    if not mixed:
        lines.append("No single function had both semantic buckets via surviving string references.")
    for entry, info, buckets in sorted(mixed):
        ins = function(md, data, entry)
        lines += [f"### `0x{entry:08X}` buckets={sorted(buckets)}", ""]
        for row in info["strings"]:
            txt = row["text"].replace("`", "'")
            lines.append(f"- `0x{row['offset']:08X}` {row['keywords']}: `{txt[:260]}`")
        lines += ["", "Direct calls:"]
        for at, target in function_calls(data, ins):
            lines.append(f"- `0x{at:08X}` → `0x{target:08X}`")
        lines.append("")

    lines += [
        "## Keyword string/xref inventory",
        "",
        "| string offset | keywords | refs | text |",
        "|---:|---|---|---|",
    ]
    for row in strings[:800]:
        txt = row["text"].replace("|", "\\|").replace("`", "'")
        refs = [hex(x) for x in row.get("refs", [])[:20]]
        lines.append(f"| `0x{row['offset']:08X}` | `{row['keywords']}` | `{refs}` | {txt[:300]} |")

    lines += [
        "",
        "## Decision boundary",
        "",
        "If Leica's still chain consumes R2Y YYW Y/Cb/Cr directly, the Android visible-RGB path should be treated as a decode/presentation transform of Leica's final YCC signal, not as an additional photographic RGB transfer stage. Conversely, a Leica-specific YCC→RGB or output-transfer consumer must be located before adding one. Absence of a surviving string is not proof; use call/dataflow evidence where available.",
        "",
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
