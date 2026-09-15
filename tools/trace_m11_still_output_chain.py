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
JPEG_KEYS = {"jpeg", "jpg", "stillencoder", "still encoder", "encoder_still", "fj_encoder_still", "encode", "jfif"}
R2Y_KEYS = {"r2y", "ycc", "ycbcr", "yyw", "chroma", "b2b_r2y", "img_wfq_job_b2b_r2y"}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
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


def nearest_prologue(md: Cs, data: bytes, target: int, window: int = 0x5000) -> int | None:
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


def direct_callers(data: bytes, target: int, cap: int = 100) -> list[int]:
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
                yield x.address, (hi << 16) | lo
                break


def semantic_strings_in_function(insns, all_strings: dict[int, str], runtime_to_raw: dict[int, int]):
    found: dict[int, tuple[int, str]] = {}
    for at, value in movw_movt_constants(insns):
        raw = value if value in all_strings else runtime_to_raw.get(value)
        if raw is not None:
            text = all_strings[raw]
            low = text.lower()
            if any(k in low for k in KEYWORDS):
                found[raw] = (at, text)
    return [(raw, at, text) for raw, (at, text) in sorted(found.items())]


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

    # Build a compact string dictionary once. Keep all strings so known-function
    # MOVW/MOVT constants can resolve even if a keyword appears late in a format string.
    all_strings: dict[int, str] = {}
    semantic = []
    for off, text in ascii_strings(data):
        all_strings[off] = text
        low = text.lower()
        keys = sorted({k for k in KEYWORDS if k in low})
        if keys:
            semantic.append({"offset": off, "text": text[:500], "keywords": keys})
    runtime_to_raw = {((off + DATA_AFFINE) & 0xFFFFFFFF): off for off in all_strings}

    # Aligned literal-pool references only. This is cheap and gives candidate
    # JPEG/still functions without globally disassembling tens of MB of code.
    wanted = {row["offset"] for row in semantic}
    wanted_runtime = {((off + DATA_AFFINE) & 0xFFFFFFFF): off for off in wanted}
    literal_refs: dict[int, list[int]] = defaultdict(list)
    for p in range(0, len(data) - 3, 4):
        word = u32(data, p)
        raw = word if word in wanted else wanted_runtime.get(word)
        if raw is not None and len(literal_refs[raw]) < 50:
            literal_refs[raw].append(p)
    for row in semantic:
        row["literal_refs"] = literal_refs.get(row["offset"], [])

    # Candidate JPEG/still semantic functions from literal refs only.
    jpeg_candidates: dict[int, list[dict]] = defaultdict(list)
    for row in semantic:
        if not (set(row["keywords"]) & JPEG_KEYS):
            continue
        for ref in row["literal_refs"][:20]:
            entry = nearest_prologue(md, data, ref)
            if entry is not None:
                jpeg_candidates[entry].append(row)

    # Trace known still job, its parent functions, and one caller generation above
    # those parents. This is the relevant chain and keeps the probe deterministic.
    chain: dict[int, dict] = {}

    def add_function(entry: int, reason: str):
        if entry in chain:
            chain[entry]["reasons"].add(reason)
            return
        ins = function(md, data, entry)
        chain[entry] = {
            "reasons": {reason},
            "ins": ins,
            "calls": function_calls(data, ins),
            "strings": semantic_strings_in_function(ins, all_strings, runtime_to_raw),
        }

    add_function(STILL_B2B_R2Y_JOB, "known still B2B/R2Y job")
    first_callers = direct_callers(data, STILL_B2B_R2Y_JOB)
    parent_entries = []
    for callsite in first_callers:
        entry = nearest_prologue(md, data, callsite)
        if entry is not None:
            parent_entries.append(entry)
            add_function(entry, f"direct caller at 0x{callsite:08X}")

    grand_entries = []
    for parent in sorted(set(parent_entries)):
        for callsite in direct_callers(data, parent):
            entry = nearest_prologue(md, data, callsite)
            if entry is not None:
                grand_entries.append(entry)
                add_function(entry, f"caller of parent 0x{parent:08X} at 0x{callsite:08X}")

    # Direct call intersection with JPEG semantic candidates.
    jpeg_entries = set(jpeg_candidates)
    intersections = []
    for entry, info in chain.items():
        for at, target in info["calls"]:
            if target in jpeg_entries:
                intersections.append((entry, at, target))

    lines = [
        "# M11-P still R2Y → output/JPEG boundary trace",
        "",
        f"- canonical unpacked SHA-256: `{digest}`",
        f"- known still B2B/R2Y job: `0x{STILL_B2B_R2Y_JOB:08X}`",
        f"- data/string affine: `0x{DATA_AFFINE:08X}`",
        f"- semantic ASCII strings: `{len(semantic)}`",
        f"- JPEG/still candidate functions from literal xrefs: `{len(jpeg_candidates)}`",
        f"- traced known-chain functions: `{len(chain)}`",
        f"- direct known-chain → JPEG-candidate call intersections: `{len(intersections)}`",
        "",
        "## Architectural constraint from public Milbeaut driver",
        "",
        "R2Y YYW writes Y/Cb/Cr planes, exposes YCC444/YCC422/YCC420 thinning, exposes 8/10-bit YCbCr format selection, and 8/10/12/16-bit output packing. Therefore the Android renderer must not invent a Leica RGB output transfer after R2Y unless the Leica still chain demonstrates one before JPEG encoding.",
        "",
        "## Direct chain/JPEG intersections",
        "",
    ]
    if not intersections:
        lines.append("No direct call from the two-generation known R2Y chain to a literal-string-identified JPEG candidate was found.")
    for entry, at, target in intersections:
        lines.append(f"- chain `0x{entry:08X}` call `0x{at:08X}` → JPEG candidate `0x{target:08X}`")

    for entry in sorted(chain):
        info = chain[entry]
        lines += [
            "",
            f"## Chain function `0x{entry:08X}`",
            "",
            f"Reasons: `{sorted(info['reasons'])}`",
            "",
            "### Semantic MOVW/MOVT strings",
            "",
        ]
        if info["strings"]:
            for raw, at, text in info["strings"]:
                lines.append(f"- `0x{at:08X}` → string `0x{raw:08X}`: `{text[:260].replace('`', "'")}`")
        else:
            lines.append("No keyword-bearing constructed string pointer in this function.")
        lines += ["", "### Direct BL targets", ""]
        for at, target in info["calls"]:
            marker = " **JPEG candidate**" if target in jpeg_entries else ""
            lines.append(f"- `0x{at:08X}` → `0x{target:08X}`{marker}")
        lines += ["", "### Disassembly", "", "```asm"]
        lines += [fmt(x) for x in info["ins"]]
        lines += ["```", ""]

    lines += ["## JPEG/still candidate functions from literal xrefs", ""]
    if not jpeg_candidates:
        lines.append("No literal-string-identified JPEG/still function candidates.")
    for entry, rows in sorted(jpeg_candidates.items()):
        lines.append(f"### `0x{entry:08X}`")
        for row in rows[:20]:
            refs = [hex(x) for x in row["literal_refs"][:12]]
            txt = row["text"].replace("`", "'")
            lines.append(f"- `{row['keywords']}` refs={refs}: `{txt[:260]}`")
        lines.append("")

    lines += [
        "## Semantic string inventory",
        "",
        "| offset | keywords | literal refs | text |",
        "|---:|---|---|---|",
    ]
    for row in semantic[:800]:
        txt = row["text"].replace("|", "\\|").replace("`", "'")
        lines.append(
            f"| `0x{row['offset']:08X}` | `{row['keywords']}` | "
            f"`{[hex(x) for x in row['literal_refs'][:12]]}` | {txt[:300]} |"
        )

    lines += [
        "",
        "## Decision boundary",
        "",
        "If Leica's still chain consumes R2Y YYW Y/Cb/Cr directly, Android RGB is a presentation/decode transform of Leica's final YCC signal, not an additional photographic stage. If this probe locates an intervening Leica-specific YCC→RGB/output-transfer consumer, trace that consumer before changing the renderer. A missing string reference alone is not proof.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
