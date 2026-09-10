#!/usr/bin/env python3
"""Match exact-GCC Milbeaut Chroma Suppress functions against M11-P firmware.

This reuses the relocation-aware matching primitives from the existing gamma
fingerprint work.  Public Milbeaut source remains generic secondary evidence;
matching it to the exact M11-P image is intended to locate a Leica-side CSP
consumer/setter region for subsequent callsite and runtime-selector tracing.
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
    "im_r2y_ctrl3_chroma_suppress",
    "imR2ySetRdmaValChromaSuppressCtrl",
}


def is_csp_name(name: str) -> bool:
    low = name.lower()
    return name in TARGET_NAMES or ("chroma" in low and "suppress" in low)


def report(m11: bytes, obj: Path) -> str:
    funcs = load_functions(obj)
    selected = [f for f in funcs if is_csp_name(f.name)]
    lines = [
        "# M11-P exact-GCC Milbeaut CSP fingerprint report",
        "",
        f"- exact M11-P unpacked SHA-256: `{hashlib.sha256(m11).hexdigest()}`",
        "- public source: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`",
        "- target object: `imr2yctrl3.o`",
        "- target API: Milbeaut `R2yCtrlCs` / Chroma Suppress",
        "",
        "## Selected public functions",
        "",
    ]
    if not selected:
        lines.append("No Chroma Suppress function symbols found.")
    for fn in selected:
        lines.append(
            f"- `{fn.name}` size `{fn.size}` section `{fn.section_name}` masked/link-sensitive words `{len(fn.masked_words)}`"
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
                f"- object word `{row['object_word']}` length `{row['words']}` words => M11 hit count `{len(row['hits'])}`"
            )
            lines.append("  - M11 offsets: " + ", ".join(f"`0x{x:08x}`" for x in row["hits"][:24]))
            lines.append(f"  - reference disassembly: `{row['disasm']}`")
        shape = fuzzy_anchor(fn)
        lines.append(f"- 12-word coarse opcode-shape anchor: `{' '.join(f'{x:08x}' for x in shape)}`")
        lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "Multiple independent exact relocation-free windows converging on one M11 code region would be strong compiler/source correlation for the CSP setter. It would still not prove Leica's Standard runtime state until callers, selector data and parameter copies are traced. No renderer arithmetic should be changed from a fuzzy-only match.",
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
    text = report(m11, args.object)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
