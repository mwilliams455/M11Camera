#!/usr/bin/env python3
"""Match exact-GCC Milbeaut YC-convert functions against M11-P firmware.

Category 24 is a single 9 x int16 R2YS map whose values exactly match the
public Milbeaut R2yCtrlYcc::ycCoeff[3][3] sample matrix.  This probe correlates
the public YC-convert API/setter object code with the exact Leica M11-P image.
Public Milbeaut source is secondary evidence; the Leica firmware remains the
primary target and renderer arithmetic must not change from a fuzzy-only hit.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from match_milbeaut_object_fingerprints import (
    EXPECTED_M11_SHA,
    exact_run_matches,
    fuzzy_anchor,
    load_functions,
    unmasked_runs,
)

TARGET_NAMES = {
    "im_r2y_ctrl2_yc_convert",
    "imR2ySetRdmaValYcConvertCtrl",
}


def is_ycc_name(name: str) -> bool:
    low = name.lower()
    return name in TARGET_NAMES or "ycconvert" in low or "yc_convert" in low


def report(m11: bytes, obj: Path) -> str:
    funcs = load_functions(obj)
    selected = [f for f in funcs if is_ycc_name(f.name)]
    lines = [
        "# M11-P Category-24 YC-convert exact-GCC fingerprint report",
        "",
        f"- exact M11-P unpacked SHA-256: `{hashlib.sha256(m11).hexdigest()}`",
        "- public source: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`",
        "- target object: `imr2yctrl2.o`",
        "- target API: Milbeaut `R2yCtrlYcc` / YC Convert",
        "- public register family: `YC[3x3]` followed by `YBLEND`",
        "",
        "## Selected public functions",
        "",
    ]
    if not selected:
        lines.append("No YC-convert function symbols found.")
    for fn in selected:
        lines.append(
            f"- `{fn.name}` size `{fn.size}` section `{fn.section_name}` "
            f"masked/link-sensitive words `{len(fn.masked_words)}`"
        )

    lines += ["", "## Relocation-free matches", ""]
    for fn in selected:
        rows = exact_run_matches(m11, fn)
        lines += [
            f"### `{fn.name}`",
            "",
            f"- usable unmasked runs >=4 words: `{len(unmasked_runs(fn, 4))}`",
            f"- exact matching runs: `{len(rows)}`",
        ]
        for row in rows[:20]:
            lines.append(
                f"- object word `{row['object_word']}` length `{row['words']}` words "
                f"=> M11 hit count `{len(row['hits'])}`"
            )
            lines.append("  - M11 offsets: " + ", ".join(f"`0x{x:08x}`" for x in row["hits"][:24]))
            lines.append(f"  - reference disassembly: `{row['disasm']}`")
        shape = fuzzy_anchor(fn)
        lines.append(f"- 12-word coarse opcode-shape anchor: `{' '.join(f'{x:08x}' for x in shape)}`")
        lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "Multiple independent exact relocation-free windows converging on one M11 code region are strong compiler/source correlation for the YC-convert consumer. This identifies the consumer family but does not by itself prove pixel-stage order versus CSP; register topology/callers are separate evidence. No renderer change is justified by fuzzy-only correlation.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("m11", type=Path)
    ap.add_argument("object", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    m11 = args.m11.read_bytes()
    digest = hashlib.sha256(m11).hexdigest()
    if digest != EXPECTED_M11_SHA:
        raise ValueError(f"unexpected M11 unpacked SHA-256 {digest}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report(m11, args.object) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
