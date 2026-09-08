#!/usr/bin/env python3
"""Find A32 code xrefs to the Leica M11 R2Y selector string cluster.

Evidence-only tool.  It hash-gates the decompressed M11-P 2.6.1 image and emits
only derived offsets/disassembly.  No firmware bytes are written to the report.

The useful trick is that an ARM literal load identifies its pool slot without
knowing the image load address.  For every ``LDR Rt, [PC, #+/-imm12]`` we read
the pool word, then test whether ``pool_value - string_file_offset`` is the
same affine load-base delta for several independent selector strings.  A base
supported by multiple strings is far stronger than guessing a virtual address.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"

# Exact strings from the contiguous selector diagnostic cluster.  Include the
# neighbouring YC/tone/YNR selectors so an affine pointer-base candidate can be
# independently corroborated instead of being promoted from one gamma string.
TARGETS = [
    ("tone_err2", b"----ERROR---- img_macro_drv_r2y_select_tone_ctrl_paraset 2"),
    ("tone_err1", b"----ERROR-----   img_macro_drv_r2y_select_tone_ctrl_paraset 1"),
    ("yc_loaded", b"(r2y) R2Y YC already loaded"),
    ("yc_err1", b"----ERROR-----   img_macro_drv_r2y_select_yc_paraset 1"),
    ("gamma_loaded", b"(r2y) R2Y GAMMA already loaded"),
    ("gamma_invalid", b"NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset"),
    ("gamma_err2", b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2"),
    ("gamma_err3", b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3"),
    ("gamma_rgbyb", b"-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1"),
    ("ynr_loaded", b"(r2y) R2Y YNR already loaded"),
]


@dataclass(frozen=True)
class LiteralXref:
    insn_off: int
    pool_off: int
    pool_value: int
    target_name: str
    string_off: int
    base_delta: int
    rt: int


def find_unique(data: bytes, needle: bytes) -> int:
    first = data.find(needle)
    if first < 0:
        raise ValueError(f"target string not found: {needle!r}")
    second = data.find(needle, first + 1)
    if second >= 0:
        raise ValueError(f"target string is not unique: {needle!r}: 0x{first:x}, 0x{second:x}")
    return first


def s32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def is_a32_ldr_literal(word: int) -> bool:
    # cond ignored; I=0,P=1,U=*,B=0,W=0,L=1,Rn=PC.
    return (word & 0x0F7F0000) == 0x051F0000


def scan_literal_xrefs(data: bytes, string_offsets: dict[str, int]) -> list[LiteralXref]:
    # Index string offsets so each literal value generates base candidates only
    # for our small explicit target set.
    out: list[LiteralXref] = []
    n = len(data) & ~3
    for off in range(0, n, 4):
        word = struct.unpack_from("<I", data, off)[0]
        if not is_a32_ldr_literal(word):
            continue
        imm12 = word & 0xFFF
        add = bool(word & (1 << 23))
        pool = off + 8 + (imm12 if add else -imm12)
        if pool < 0 or pool + 4 > len(data) or (pool & 3):
            continue
        value = struct.unpack_from("<I", data, pool)[0]
        rt = (word >> 12) & 0xF
        for name, string_off in string_offsets.items():
            delta = (value - string_off) & 0xFFFFFFFF
            out.append(LiteralXref(off, pool, value, name, string_off, delta, rt))
    return out


def choose_bases(xrefs: list[LiteralXref], minimum_strings: int = 3) -> list[tuple[int, list[LiteralXref]]]:
    by_base: dict[int, list[LiteralXref]] = defaultdict(list)
    for x in xrefs:
        by_base[x.base_delta].append(x)
    ranked = []
    for base, items in by_base.items():
        names = {x.target_name for x in items}
        if len(names) >= minimum_strings:
            ranked.append((base, items))
    ranked.sort(key=lambda bi: (-len({x.target_name for x in bi[1]}), -len(bi[1]), bi[0]))
    return ranked


def decode_bl_target(off: int, word: int) -> int | None:
    # A32 B/BL immediate, condition ignored.  BL has bits 27:24 == 1011.
    if (word & 0x0F000000) != 0x0B000000:
        return None
    imm24 = word & 0x00FFFFFF
    if imm24 & 0x00800000:
        imm24 -= 0x01000000
    return off + 8 + (imm24 << 2)


def nearest_prologue(data: bytes, center: int, radius: int = 0x800) -> int | None:
    # Common A32 GCC function prologue: STMDB sp!, {...,lr}; PUSH alias.
    start = max(0, (center - radius) & ~3)
    best = None
    for off in range(start, center + 1, 4):
        w = struct.unpack_from("<I", data, off)[0]
        # cond ignored; STMDB sp!, reglist, LR present.
        if (w & 0x0FFF4000) == 0x092D4000:
            best = off
    return best


def disasm_window(data: bytes, start: int, end: int, string_offsets: dict[str, int], base: int) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    start = max(0, start & ~3)
    end = min(len(data), (end + 3) & ~3)
    labels_by_off = {v: k for k, v in string_offsets.items()}
    lines: list[str] = []
    for insn in md.disasm(data[start:end], start):
        if insn.address & 3:
            continue
        off = insn.address
        annotation = ""
        w = struct.unpack_from("<I", data, off)[0]
        if is_a32_ldr_literal(w):
            imm12 = w & 0xFFF
            pool = off + 8 + (imm12 if (w & (1 << 23)) else -imm12)
            if 0 <= pool <= len(data) - 4 and not (pool & 3):
                value = struct.unpack_from("<I", data, pool)[0]
                target_file = (value - base) & 0xFFFFFFFF
                if target_file in labels_by_off:
                    annotation = f" ; -> {labels_by_off[target_file]}@0x{target_file:08x} via pool 0x{pool:08x}"
        bl = decode_bl_target(off, w)
        if bl is not None:
            annotation += f" ; BL file-target 0x{bl:08x}"
        lines.append(f"0x{off:08x}: {insn.mnemonic} {insn.op_str}{annotation}".rstrip())
    return lines


def emit_report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    string_offsets = {name: find_unique(data, needle) for name, needle in TARGETS}
    all_candidates = scan_literal_xrefs(data, string_offsets)
    ranked = choose_bases(all_candidates, minimum_strings=3)

    lines: list[str] = []
    lines += [
        "# M11-P R2A A32 selector xref trace",
        "",
        "Evidence state: **derived from exact hash-gated M11-P 2.6.1 firmware**.",
        "",
        f"- unpacked SHA-256: `{digest}`",
        f"- unpacked size: `{len(data)}`",
        "- method: A32 PC-relative literal loads + repeated affine string-pointer base",
        "",
        "## Selector string offsets",
        "",
    ]
    for name, off in string_offsets.items():
        lines.append(f"- `{name}`: `0x{off:08x}`")

    lines += ["", "## Corroborated affine-base candidates", ""]
    if not ranked:
        lines.append("No A32 literal-pointer base is supported by three independent target strings.")
        lines.append("")
        lines.append("Interpretation: literal-pointer A32 xrefs are not proven by this pass; try ADR/MOVW+MOVT/Thumb or segment-specific mapping next.")
        return "\n".join(lines) + "\n"

    # Only display strong candidates. Random weak bases are not useful evidence.
    for idx, (base, items) in enumerate(ranked[:8], start=1):
        names = sorted({x.target_name for x in items})
        unique_sites = sorted({x.insn_off for x in items})
        lines.append(
            f"{idx}. base delta `0x{base:08x}` / signed `{s32(base):+d}` — "
            f"{len(names)} target strings, {len(unique_sites)} A32 load site(s): " + ", ".join(f"`{n}`" for n in names)
        )
    lines.append("")

    base, items = ranked[0]
    # Deduplicate the winning base by (load site, target), because each LDR is
    # tested against every target during candidate generation.
    wins = sorted({(x.insn_off, x.pool_off, x.pool_value, x.target_name, x.string_off, x.rt): x for x in items}.values(), key=lambda x: (x.insn_off, x.target_name))
    lines += [
        "## Winning-base A32 xrefs",
        "",
        f"Promoted diagnostic base candidate: `0x{base:08x}` (signed `{s32(base):+d}`).",
        "",
        "| code file off | literal pool off | target string | string file off | Rt |",
        "|---:|---:|---|---:|---:|",
    ]
    for x in wins:
        lines.append(f"| `0x{x.insn_off:08x}` | `0x{x.pool_off:08x}` | `{x.target_name}` | `0x{x.string_off:08x}` | r{x.rt} |")

    # Group nearby xrefs into code clusters. A 0x800 gap is deliberately
    # conservative: selectors often have several error paths in one function.
    sites = sorted({x.insn_off for x in wins})
    clusters: list[list[int]] = []
    for site in sites:
        if not clusters or site - clusters[-1][-1] > 0x800:
            clusters.append([site])
        else:
            clusters[-1].append(site)

    lines += ["", "## Candidate code-owner clusters", ""]
    for ci, sites_group in enumerate(clusters, start=1):
        lo, hi = sites_group[0], sites_group[-1]
        pro = nearest_prologue(data, lo)
        start = pro if pro is not None else max(0, lo - 0x100)
        end = min(len(data), hi + 0x180)
        lines.append(f"### Cluster {ci}: xrefs `0x{lo:08x}`–`0x{hi:08x}`")
        lines.append("")
        if pro is not None:
            lines.append(f"- nearest common A32 GCC prologue candidate: `0x{pro:08x}`")
        else:
            lines.append("- no common A32 STMDB/PUSH prologue found within 0x800 bytes")
        lines.append(f"- disassembly window: `0x{start:08x}`–`0x{end:08x}`")
        lines.append("")
        lines.append("```text")
        lines.extend(disasm_window(data, start, end, string_offsets, base))
        lines.append("```")
        lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "A repeated affine base backed by independent selector strings proves code-to-string A32 literal xrefs. "
        "A nearby prologue is a function-boundary candidate, not a symbol identification by itself. BL targets are "
        "relative A32 file-offset targets and become useful for correlation with exact public Milbeaut fingerprints. "
        "This report does not by itself prove photographic execution order or renderer math.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    report = emit_report(args.unpacked.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
