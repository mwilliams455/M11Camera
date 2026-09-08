#!/usr/bin/env python3
"""Refine M11 A32 selector xrefs using logger-call semantics.

The first A32 pass discovers affine pointer bases. This pass rejects structured
address coincidences by requiring independent target-string literal loads to
feed the same nearby BL call target, the characteristic diagnostic/logger
shape visible in Leica's selector code. It also searches MOVW/MOVT pairs for
strings not loaded through literal pools and emits small xref-centred windows.
Only derived metadata/disassembly is written.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
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
class Xref:
    off: int
    pool: int
    value: int
    name: str
    string_off: int
    base: int
    rt: int


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def find_unique(data: bytes, needle: bytes) -> int:
    off = data.find(needle)
    if off < 0 or data.find(needle, off + 1) >= 0:
        raise ValueError(f"target not uniquely present: {needle!r}")
    return off


def is_ldr_literal(w: int) -> bool:
    return (w & 0x0F7F0000) == 0x051F0000


def bl_target(off: int, w: int) -> int | None:
    if (w & 0x0F000000) != 0x0B000000:
        return None
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def nearby_bls(data: bytes, off: int, span: int = 0x30) -> list[int]:
    out = []
    for p in range(off + 4, min(len(data) - 3, off + span + 1), 4):
        t = bl_target(p, u32(data, p))
        if t is not None:
            out.append(t)
    return out


def scan(data: bytes, strings: dict[str, int]) -> list[Xref]:
    out = []
    for off in range(0, (len(data) - 4) & ~3, 4):
        w = u32(data, off)
        if not is_ldr_literal(w):
            continue
        imm = w & 0xFFF
        pool = off + 8 + (imm if (w & 0x00800000) else -imm)
        if pool < 0 or pool + 4 > len(data) or pool & 3:
            continue
        value = u32(data, pool)
        rt = (w >> 12) & 0xF
        for name, so in strings.items():
            out.append(Xref(off, pool, value, name, so, (value - so) & 0xFFFFFFFF, rt))
    return out


def rank_logger_bases(data: bytes, xrefs: list[Xref]) -> list[tuple[tuple[int,int,int,int], int, int, list[Xref]]]:
    by_base = defaultdict(list)
    for x in xrefs:
        by_base[x.base].append(x)
    ranked = []
    for base, items in by_base.items():
        if len({x.name for x in items}) < 3:
            continue
        call_rows = []
        for x in items:
            # Leica diagnostic format pointers are commonly loaded into r2; retain
            # r1/r3 as secondary evidence but require a common nearby BL target.
            if x.rt not in (1, 2, 3):
                continue
            for bt in nearby_bls(data, x.off):
                call_rows.append((x, bt))
        if not call_rows:
            continue
        counts = Counter(bt for _, bt in call_rows)
        logger, ncall = counts.most_common(1)[0]
        logger_items = [x for x, bt in call_rows if bt == logger]
        distinct = len({x.name for x in logger_items})
        r2distinct = len({x.name for x in logger_items if x.rt == 2})
        if distinct < 2:
            continue
        score = (r2distinct, distinct, ncall, len({x.name for x in items}))
        ranked.append((score, base, logger, logger_items))
    ranked.sort(reverse=True, key=lambda row: row[0])
    return ranked


def mov_imm16(w: int) -> tuple[str, int, int] | None:
    op = w & 0x0FF00000
    if op not in (0x03000000, 0x03400000):
        return None
    kind = "movw" if op == 0x03000000 else "movt"
    rd = (w >> 12) & 0xF
    imm = ((w >> 4) & 0xF000) | (w & 0xFFF)
    return kind, rd, imm


def movw_movt_xrefs(data: bytes, address: int) -> list[tuple[int, int, int]]:
    lo, hi = address & 0xFFFF, (address >> 16) & 0xFFFF
    out = []
    end = (len(data) - 4) & ~3
    for off in range(0, end, 4):
        dec = mov_imm16(u32(data, off))
        if dec is None or dec[0] != "movw" or dec[2] != lo:
            continue
        rd = dec[1]
        for p in range(off + 4, min(end, off + 0x20) + 1, 4):
            d2 = mov_imm16(u32(data, p))
            if d2 is not None and d2[0] == "movt" and d2[1] == rd and d2[2] == hi:
                out.append((off, p, rd))
                break
    return out


def nearest_prologue(data: bytes, center: int, radius: int = 0x800) -> int | None:
    best = None
    for off in range(max(0, center - radius) & ~3, center + 1, 4):
        w = u32(data, off)
        if (w & 0x0FFF4000) == 0x092D4000:
            best = off
    return best


def window(data: bytes, center: int, strings: dict[str, int], base: int, radius: int = 0x40) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    start = max(0, center - radius) & ~3
    end = min(len(data), center + radius + 4)
    labels = {((base + so) & 0xFFFFFFFF): name for name, so in strings.items()}
    out = []
    for ins in md.disasm(data[start:end], start):
        off = ins.address
        mark = "  <== XREF" if off == center else ""
        note = ""
        if off + 4 <= len(data) and not (off & 3):
            w = u32(data, off)
            if is_ldr_literal(w):
                imm = w & 0xFFF
                pool = off + 8 + (imm if (w & 0x00800000) else -imm)
                if 0 <= pool <= len(data)-4 and not (pool & 3):
                    pv = u32(data, pool)
                    if pv in labels:
                        note += f" ; string={labels[pv]} pool=0x{pool:08x}"
            bt = bl_target(off, w)
            if bt is not None:
                note += f" ; BL=0x{bt:08x}"
        out.append(f"0x{off:08x}: {ins.mnemonic} {ins.op_str}{note}{mark}".rstrip())
    return out


def emit(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    strings = {n: find_unique(data, s) for n, s in TARGETS}
    ranked = rank_logger_bases(data, scan(data, strings))
    lines = ["# M11-P R2A refined A32 gamma xrefs", "", f"- SHA-256: `{digest}`", ""]
    if not ranked:
        lines += ["No affine base survived the shared-logger semantic filter.", ""]
        return "\n".join(lines)
    lines += ["## Shared-logger base ranking", ""]
    for score, base, logger, items in ranked[:8]:
        names = sorted({x.name for x in items})
        lines.append(f"- base `0x{base:08x}`, logger BL `0x{logger:08x}`, score `{score}`, targets: " + ", ".join(f"`{n}`" for n in names))
    score, base, logger, items = ranked[0]
    # De-duplicate xrefs that see the same logger more than once in the lookahead.
    chosen = sorted({(x.off, x.name): x for x in items}.values(), key=lambda x: (x.off, x.name))
    lines += ["", "## Promoted logger-backed literal xrefs", "", f"Promoted base: `0x{base:08x}`; shared diagnostic BL target: `0x{logger:08x}`.", ""]
    for x in chosen:
        pro = nearest_prologue(data, x.off)
        lines.append(f"### `{x.name}` literal xref at `0x{x.off:08x}`")
        lines.append("")
        lines.append(f"- pool: `0x{x.pool:08x}`; Rt=r{x.rt}; nearest prologue candidate: `{('0x%08x' % pro) if pro is not None else 'none'}`")
        lines.append("```text")
        lines.extend(window(data, x.off, strings, base))
        lines.append("```")
        lines.append("")

    lines += ["## MOVW/MOVT selector-string address xrefs", ""]
    for name, so in strings.items():
        addr = (base + so) & 0xFFFFFFFF
        hits = movw_movt_xrefs(data, addr)
        lines.append(f"### `{name}` virtual candidate `0x{addr:08x}` — {len(hits)} pair(s)")
        lines.append("")
        for movw_off, movt_off, rd in hits[:20]:
            lines.append(f"- MOVW `0x{movw_off:08x}` -> MOVT `0x{movt_off:08x}`, r{rd}, nearest prologue `{('0x%08x' % nearest_prologue(data, movw_off)) if nearest_prologue(data, movw_off) is not None else 'none'}`")
        lines.append("")

    lines += ["## Interpretation boundary", "", "The promoted base is supported by multiple independent selector-format pointers that feed the same nearby A32 BL target. This materially reduces false affine matches from unrelated structured address tables. Function-prologue positions remain candidates until callgraph/fingerprint correlation names the routines.", ""]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(emit(a.unpacked.read_bytes()))
    print(f"wrote {a.output}")

if __name__ == "__main__":
    main()
