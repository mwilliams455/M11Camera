#!/usr/bin/env python3
"""Trace M11 gamma diagnostic xrefs using one reconciled affine base.

Unlike the earlier exploratory scorer, this pass does not form the Cartesian
product of every literal value and every diagnostic string.  The full gamma
strings are located first, translated by the single reconciled base
0x3efd2a98, and only literal/MOVW+MOVT constructions equal to those exact
virtual addresses are accepted as xrefs.

This is still ownership evidence, not a function-name proof.
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
AFFINE_BASE = 0x3EFD2A98
EXPECTED_LOGGER = 0x01679B58
TARGETS = [
    ("gamma_loaded", b"(r2y) R2Y GAMMA already loaded"),
    ("gamma_invalid", b"NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset"),
    ("gamma_err2", b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2"),
    ("gamma_err3", b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3"),
    ("gamma_rgbyb", b"-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1"),
]


@dataclass(frozen=True)
class LiteralXref:
    off: int
    pool: int
    value: int
    rt: int
    name: str


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def find_unique(data: bytes, needle: bytes) -> int:
    off = data.find(needle)
    if off < 0:
        raise ValueError(f"target missing: {needle!r}")
    if data.find(needle, off + 1) >= 0:
        raise ValueError(f"target not unique: {needle!r}")
    return off


def is_ldr_literal(w: int) -> bool:
    return (w & 0x0F7F0000) == 0x051F0000


def ldr_pool(off: int, w: int) -> int:
    imm = w & 0xFFF
    return off + 8 + (imm if (w & 0x00800000) else -imm)


def bl_target(off: int, w: int) -> int | None:
    if (w & 0x0F000000) != 0x0B000000:
        return None
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def nearby_bls(data: bytes, off: int, before: int = 0x10, after: int = 0x40) -> list[tuple[int, int]]:
    rows: list[tuple[int, int]] = []
    start = max(0, off - before) & ~3
    end = min(len(data) - 4, off + after) & ~3
    for p in range(start, end + 1, 4):
        target = bl_target(p, u32(data, p))
        if target is not None:
            rows.append((p, target))
    return rows


def nearest_prologue(data: bytes, center: int, radius: int = 0x1000) -> int | None:
    # A32 STMFD/PUSH-like save containing LR.  Deliberately heuristic: emitted as
    # a prologue candidate only, never as an exact function boundary.
    best = None
    start = max(0, center - radius) & ~3
    for off in range(start, center + 1, 4):
        w = u32(data, off)
        if (w & 0x0FFF4000) == 0x092D4000:
            best = off
    return best


def scan_literal_xrefs(data: bytes, virtuals: dict[int, str]) -> list[LiteralXref]:
    out: list[LiteralXref] = []
    end = (len(data) - 4) & ~3
    for off in range(0, end + 1, 4):
        w = u32(data, off)
        if not is_ldr_literal(w):
            continue
        pool = ldr_pool(off, w)
        if pool < 0 or pool + 4 > len(data) or (pool & 3):
            continue
        value = u32(data, pool)
        name = virtuals.get(value)
        if name is None:
            continue
        out.append(LiteralXref(off, pool, value, (w >> 12) & 0xF, name))
    return out


def mov_imm16(w: int) -> tuple[str, int, int] | None:
    op = w & 0x0FF00000
    if op not in (0x03000000, 0x03400000):
        return None
    kind = "movw" if op == 0x03000000 else "movt"
    rd = (w >> 12) & 0xF
    imm = ((w >> 4) & 0xF000) | (w & 0xFFF)
    return kind, rd, imm


def scan_mov_pairs(data: bytes, address: int) -> list[tuple[int, int, int]]:
    lo, hi = address & 0xFFFF, (address >> 16) & 0xFFFF
    out: list[tuple[int, int, int]] = []
    end = (len(data) - 4) & ~3
    for off in range(0, end + 1, 4):
        dec = mov_imm16(u32(data, off))
        if dec is None or dec[0] != "movw" or dec[2] != lo:
            continue
        rd = dec[1]
        for p in range(off + 4, min(end, off + 0x24) + 1, 4):
            d2 = mov_imm16(u32(data, p))
            if d2 is not None and d2[0] == "movt" and d2[1] == rd and d2[2] == hi:
                out.append((off, p, rd))
                break
    return out


def disasm_window(data: bytes, center: int, virtuals: dict[int, str], radius: int = 0x60) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    start = max(0, center - radius) & ~3
    end = min(len(data), center + radius + 4)
    lines: list[str] = []
    for ins in md.disasm(data[start:end], start):
        off = ins.address
        note = ""
        if off + 4 <= len(data) and not (off & 3):
            w = u32(data, off)
            if is_ldr_literal(w):
                pool = ldr_pool(off, w)
                if 0 <= pool <= len(data) - 4 and not (pool & 3):
                    value = u32(data, pool)
                    if value in virtuals:
                        note += f" ; EXACT_STRING={virtuals[value]} pool=0x{pool:08x} value=0x{value:08x}"
            bt = bl_target(off, w)
            if bt is not None:
                note += f" ; BL=0x{bt:08x}"
        mark = "  <== EXACT XREF" if off == center else ""
        lines.append(f"0x{off:08x}: {ins.mnemonic} {ins.op_str}{note}{mark}".rstrip())
    return lines


def emit(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    raw_offsets = {name: find_unique(data, needle) for name, needle in TARGETS}
    virtual_by_name = {
        name: (AFFINE_BASE + raw) & 0xFFFFFFFF for name, raw in raw_offsets.items()
    }
    virtuals = {addr: name for name, addr in virtual_by_name.items()}
    if len(virtuals) != len(TARGETS):
        raise ValueError("translated target addresses collide")

    xrefs = scan_literal_xrefs(data, virtuals)
    by_name: dict[str, list[LiteralXref]] = defaultdict(list)
    for x in xrefs:
        by_name[x.name].append(x)

    lines = [
        "# M11-P R2A exact-base A32 gamma xrefs",
        "",
        f"- SHA-256: `{digest}`",
        f"- constrained affine base: `0x{AFFINE_BASE:08x}`",
        f"- previously observed shared diagnostic logger: `0x{EXPECTED_LOGGER:08x}`",
        "",
        "## Reconciled full-string coordinates",
        "",
        "| target | raw string start | exact virtual address | literal xrefs |",
        "|---|---:|---:|---:|",
    ]
    for name, _ in TARGETS:
        lines.append(
            f"| `{name}` | `0x{raw_offsets[name]:08x}` | `0x{virtual_by_name[name]:08x}` | {len(by_name[name])} |"
        )

    lines += ["", "## Exact literal xrefs", ""]
    for name, _ in TARGETS:
        rows = sorted(by_name[name], key=lambda x: x.off)
        lines.append(f"### `{name}` — {len(rows)} xref(s)")
        lines.append("")
        if not rows:
            lines.append("No exact PC-relative literal load of the translated string address found.")
            lines.append("")
            continue
        for x in rows:
            pro = nearest_prologue(data, x.off)
            bls = nearby_bls(data, x.off)
            logger_calls = [call for call, target in bls if target == EXPECTED_LOGGER]
            lines.append(
                f"- xref `0x{x.off:08x}`, pool `0x{x.pool:08x}`, r{x.rt}, "
                f"prologue candidate `{('0x%08x' % pro) if pro is not None else 'none'}`, "
                f"nearby expected-logger call(s): "
                + (", ".join(f"`0x{p:08x}`" for p in logger_calls) if logger_calls else "none")
            )
            lines.append("```text")
            lines.extend(disasm_window(data, x.off, virtuals))
            lines.append("```")
            lines.append("")

    lines += ["## Prologue-family grouping", ""]
    groups: dict[int | None, list[LiteralXref]] = defaultdict(list)
    for x in xrefs:
        groups[nearest_prologue(data, x.off)].append(x)
    for pro, rows in sorted(groups.items(), key=lambda kv: (-1 if kv[0] is None else kv[0])):
        names = sorted({x.name for x in rows})
        lines.append(
            f"- `{('none' if pro is None else '0x%08x' % pro)}`: "
            + ", ".join(f"`{n}`" for n in names)
            + f" ({len(rows)} exact literal xref(s))"
        )

    lines += ["", "## Exact MOVW/MOVT address constructions", ""]
    for name, _ in TARGETS:
        addr = virtual_by_name[name]
        pairs = scan_mov_pairs(data, addr)
        lines.append(f"### `{name}` `0x{addr:08x}` — {len(pairs)} pair(s)")
        lines.append("")
        for movw_off, movt_off, rd in pairs[:32]:
            pro = nearest_prologue(data, movw_off)
            lines.append(
                f"- MOVW `0x{movw_off:08x}` -> MOVT `0x{movt_off:08x}`, r{rd}, "
                f"prologue candidate `{('0x%08x' % pro) if pro is not None else 'none'}`"
            )
        lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "This pass accepts only exact address constructions for full gamma diagnostic strings under the reconciled affine base. It removes the cross-target affine aliasing mechanism in the exploratory scorer. A matching xref/prologue still establishes code-family ownership only; exact Leica function naming requires compiler/callsite convergence.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(emit(args.unpacked.read_bytes()))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
