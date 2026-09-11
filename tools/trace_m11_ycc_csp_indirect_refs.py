#!/usr/bin/env python3
"""Trace indirect/static references to the closed M11-P YC and CSP wrappers.

The first YC/CSP ancestry probe intentionally considered only direct A32 BL
edges.  Both wrappers had zero direct callers, so this second pass looks for
registration/dispatch evidence instead of treating that negative result as a
pipeline-order result.

It reports:
  * raw 32-bit target words;
  * Leica translated code pointers using the already-proven 0x3FAA87D0 affine;
  * A32 MOVW/MOVT pairs that construct either representation;
  * nearby words decoded through the same code/data affines.

This is configuration/control-flow evidence only.  It must not be promoted to
silicon pixel-stage order without an independent hardware/dataflow anchor.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
CODEPTR_BASE = 0x3FAA87D0
DATA_BASE = 0x3EFD2A98
CODE_START = 0x01000000
CODE_END = 0x02000000
TARGETS = {
    "YC_wrapper": 0x0172DFC0,
    "YC_setter": 0x01B624AC,
    "CSP_wrapper": 0x01731970,
    "CSP_setter": 0x01B68B80,
}


def u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def word_hits(d: bytes, v: int) -> list[int]:
    needle = struct.pack("<I", v & 0xFFFFFFFF)
    out: list[int] = []
    p = 0
    while True:
        p = d.find(needle, p)
        if p < 0:
            break
        if not (p & 3):
            out.append(p)
        p += 1
    return out


def printable(d: bytes, raw: int, maxlen: int = 160) -> str | None:
    if raw < 0 or raw >= len(d):
        return None
    end = d.find(b"\0", raw, min(len(d), raw + maxlen))
    if end <= raw:
        return None
    b = d[raw:end]
    if len(b) < 4:
        return None
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 or ord(c) >= 127 for c in s):
        return None
    return s


def context(d: bytes, off: int, words: int = 14) -> list[str]:
    rows = []
    lo = max(0, off - words * 4) & ~3
    hi = min(len(d) - 4, off + words * 4)
    for p in range(lo, hi + 1, 4):
        v = u32(d, p)
        ann = []
        code = (v - CODEPTR_BASE) & 0xFFFFFFFF
        if CODE_START <= code < CODE_END:
            ann.append(f"code_raw=0x{code:08x}")
        data = (v - DATA_BASE) & 0xFFFFFFFF
        if data < len(d):
            s = printable(d, data)
            if s:
                ann.append(f"string={s!r}")
        mark = " <TARGET>" if p == off else ""
        rows.append(f"0x{p:08x}: 0x{v:08x}{mark}" + ((" ; " + " ; ".join(ann)) if ann else ""))
    return rows


def mov_imm16(word: int, want_top: int) -> tuple[int, int] | None:
    # A32 MOVW/MOVT (immediate), cond ignored except NV.
    if ((word >> 28) & 0xF) == 0xF:
        return None
    if (word & 0x0FF00000) != want_top:
        return None
    rd = (word >> 12) & 0xF
    imm16 = ((word >> 4) & 0xF000) | (word & 0xFFF)
    return rd, imm16


def mov_pairs(d: bytes, value: int) -> list[tuple[int, int, int]]:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    out = []
    end = min(len(d), CODE_END) & ~3
    start = min(CODE_START, end)
    for p in range(start, end, 4):
        a = mov_imm16(u32(d, p), 0x03000000)  # MOVW class
        if a is None or a[1] != lo:
            continue
        rd = a[0]
        for q in range(p + 4, min(end, p + 28), 4):
            b = mov_imm16(u32(d, q), 0x03400000)  # MOVT class
            if b is not None and b == (rd, hi):
                out.append((p, q, rd))
                break
    return out


def disasm_window(d: bytes, centre: int, radius: int = 0x40) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    lo = max(CODE_START, centre - radius) & ~3
    hi = min(len(d), CODE_END, centre + radius)
    return [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in md.disasm(d[lo:hi], lo)]


def report(d: bytes) -> str:
    sha = hashlib.sha256(d).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError(f"unexpected M11 unpacked SHA-256 {sha}")
    lines = [
        "# M11-P YC/CSP indirect-reference trace",
        "",
        f"- SHA-256: `{sha}`",
        f"- proven translated-code affine: `0x{CODEPTR_BASE:08x}`",
        "- purpose: explain zero-direct-BL wrapper ancestry without inferring pixel order",
        "",
    ]
    for name, target in TARGETS.items():
        translated = (target + CODEPTR_BASE) & 0xFFFFFFFF
        raw_hits = word_hits(d, target)
        trans_hits = word_hits(d, translated)
        raw_mov = mov_pairs(d, target)
        trans_mov = mov_pairs(d, translated)
        lines += [
            f"## {name} `0x{target:08x}`",
            "",
            f"- translated pointer: `0x{translated:08x}`",
            f"- aligned raw-word hits: `{len(raw_hits)}`",
            f"- aligned translated-pointer hits: `{len(trans_hits)}`",
            f"- MOVW/MOVT raw-address constructions: `{len(raw_mov)}`",
            f"- MOVW/MOVT translated-pointer constructions: `{len(trans_mov)}`",
            "",
        ]
        for label, hits in (("raw word", raw_hits), ("translated pointer", trans_hits)):
            for n, p in enumerate(hits[:24], 1):
                lines += [f"### {label} hit {n} at raw `0x{p:08x}`", "", "```text"]
                lines += context(d, p)
                lines += ["```", ""]
        for label, rows in (("raw", raw_mov), ("translated", trans_mov)):
            for n, (p, q, rd) in enumerate(rows[:24], 1):
                lines += [
                    f"### {label} MOVW/MOVT construction {n}",
                    "",
                    f"- MOVW `0x{p:08x}`, MOVT `0x{q:08x}`, r{rd}",
                    "```asm",
                ]
                lines += disasm_window(d, p)
                lines += ["```", ""]
    lines += [
        "## Interpretation boundary",
        "",
        "A pointer/table hit can identify a registration or indirect-dispatch path and is the correct next control-flow lead after the direct-BL scan returned empty. It does not establish whether YC conversion is before or after CSP in the hardware pixel datapath.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report(args.unpacked.read_bytes()) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
