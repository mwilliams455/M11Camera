#!/usr/bin/env python3
"""Contextual M11-P Cat24/YC-convert trace using same-base register stores.

The first broad Cat24 footprint scan showed that +0x100..+0x120 displacements
are too common to identify a hardware setter by themselves.  This probe adds
three constraints:

1. group register stores by A32 function entry AND base register;
2. calibrate the method against the already-closed CSP setter at 0x01B68B80;
3. rank YC-convert candidates in the same low-level R2Y driver neighbourhood.

Public Milbeaut register families:
  YCC: +0x100,+0x104,+0x108,+0x10c,+0x110,+0x120
  CSP: +0x580,+0x588,+0x58c,+0x590,+0x594,+0x598,+0x59c,+0x5a0,+0x5a4,+0x5a8,+0x5ac

This is evidence gathering only.  Register-programming order is not treated as
pixel-stage order, and no renderer change is justified solely by this probe.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
KNOWN_CSP_SETTER = 0x01B68B80
KNOWN_CSP_WRAPPER = 0x01731DB0

YCC = (0x100, 0x104, 0x108, 0x10C, 0x110, 0x120)
CSP = (0x580, 0x588, 0x58C, 0x590, 0x594, 0x598, 0x59C, 0x5A0, 0x5A4, 0x5A8, 0x5AC)

# Wide enough to cover sibling functions linked from the same low-level image
# module while remaining far narrower than the 97 MB firmware-wide scan.
DRIVER_LO = KNOWN_CSP_SETTER - 0x60000
DRIVER_HI = KNOWN_CSP_SETTER + 0x60000
WRAPPER_LO = KNOWN_CSP_WRAPPER - 0x60000
WRAPPER_HI = KNOWN_CSP_WRAPPER + 0x60000


def word(data: bytes, p: int) -> int:
    return struct.unpack_from("<I", data, p)[0]


def is_push_lr(w: int) -> bool:
    # A32 STMDB sp!, {...,lr}, AL condition.
    return (w & 0xFFFF4000) == 0xE92D4000


def sdt_imm(w: int):
    cond = (w >> 28) & 0xF
    if cond == 0xF or ((w >> 26) & 3) != 1 or ((w >> 25) & 1):
        return None
    load = bool((w >> 20) & 1)
    up = bool((w >> 23) & 1)
    pre = bool((w >> 24) & 1)
    writeback = bool((w >> 21) & 1)
    rn = (w >> 16) & 0xF
    rt = (w >> 12) & 0xF
    imm = w & 0xFFF
    return load, up, pre, writeback, rn, rt, imm


def nearest_entry(data: bytes, p: int, max_back: int = 0x900) -> int:
    lo = max(0, p - max_back) & ~3
    found = None
    for q in range(lo, p + 1, 4):
        if is_push_lr(word(data, q)):
            found = q
    return found if found is not None else max(lo, p - 0x180)


def bl_callers(data: bytes, target: int) -> list[int]:
    out = []
    for p in range(0, len(data) & ~3, 4):
        w = word(data, p)
        if ((w >> 28) & 0xF) == 0xF or ((w >> 25) & 7) != 5 or ((w >> 24) & 1) == 0:
            continue
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 1 << 24
        if ((p + 8 + (imm << 2)) & 0xFFFFFFFF) == target:
            out.append(p)
    return out


def scan_family(data: bytes, offsets: tuple[int, ...], lo: int, hi: int) -> list[dict]:
    wanted = set(offsets)
    groups: dict[tuple[int, int], list[tuple[int, int, int]]] = defaultdict(list)
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    for p in range(lo, hi, 4):
        dec = sdt_imm(word(data, p))
        if dec is None:
            continue
        load, up, pre, writeback, rn, rt, imm = dec
        if load or not up or imm not in wanted:
            continue
        entry = nearest_entry(data, p)
        groups[(entry, rn)].append((p, imm, rt))

    rows = []
    for (entry, rn), hits in groups.items():
        hits.sort()
        distinct = sorted({h[1] for h in hits})
        firsts = []
        seen = set()
        for p, off, rt in hits:
            if off not in seen:
                firsts.append(off); seen.add(off)
        prefix = 0
        for got, want in zip(firsts, offsets):
            if got != want:
                break
            prefix += 1
        completeness = len(distinct) / len(offsets)
        score = len(distinct) * 100 + prefix * 40
        rows.append({
            "entry": entry,
            "rn": rn,
            "hits": hits,
            "distinct": distinct,
            "firsts": firsts,
            "prefix": prefix,
            "completeness": completeness,
            "score": score,
            "callers": bl_callers(data, entry),
        })
    rows.sort(key=lambda r: (r["score"], r["completeness"], -abs(r["entry"] - KNOWN_CSP_SETTER)), reverse=True)
    return rows


def disasm(data: bytes, lo: int, hi: int) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    lo = max(0, lo) & ~3
    hi = min(len(data), hi) & ~3
    return [f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in md.disasm(data[lo:hi], lo)]


def emit_family(lines: list[str], data: bytes, title: str, offsets: tuple[int, ...], rows: list[dict], top: int = 12):
    lines += [f"## {title}", "", "Target offsets: `" + ", ".join(hex(x) for x in offsets) + "`", ""]
    if not rows:
        lines += ["No same-base grouped candidates found.", ""]
        return
    for idx, r in enumerate(rows[:top], 1):
        lines += [
            f"### {idx}. `0x{r['entry']:08x}` base `r{r['rn']}`",
            "",
            f"- score: `{r['score']}`",
            f"- distinct offsets: `{[hex(x) for x in r['distinct']]}`",
            f"- completeness: `{r['completeness']:.3f}`",
            f"- ordered-prefix length: `{r['prefix']}`",
            f"- first-seen order: `{[hex(x) for x in r['firsts']]}`",
            f"- direct BL callers: `{len(r['callers'])}`",
        ]
        for c in r["callers"][:24]:
            lines.append(f"  - `0x{c:08x}`")
        lines += ["- matching stores:"]
        for p, off, rt in r["hits"][:64]:
            lines.append(f"  - `0x{p:08x}` STR-like r{rt} -> [r{r['rn']}, +0x{off:x}]")
        lines += ["", "```asm"]
        lines += disasm(data, r["entry"], min(len(data), r["entry"] + 0x500))[:320]
        lines += ["```", ""]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    csp_driver = scan_family(data, CSP, DRIVER_LO, DRIVER_HI)
    ycc_driver = scan_family(data, YCC, DRIVER_LO, DRIVER_HI)
    ycc_wrapper_neighbourhood = scan_family(data, YCC, WRAPPER_LO, WRAPPER_HI)

    calibration = next((r for r in csp_driver if r["entry"] == KNOWN_CSP_SETTER), None)
    calibration_ok = calibration is not None and len(calibration["distinct"]) >= 9

    lines = [
        "# M11-P Category-24 contextual YC-convert trace",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- known CSP setter calibration target: `0x{KNOWN_CSP_SETTER:08x}`",
        f"- known CSP wrapper: `0x{KNOWN_CSP_WRAPPER:08x}`",
        f"- low-level driver window: `0x{DRIVER_LO:08x}..0x{DRIVER_HI:08x}`",
        f"- Leica wrapper neighbourhood: `0x{WRAPPER_LO:08x}..0x{WRAPPER_HI:08x}`",
        f"- CSP same-base calibration: `{'PASS' if calibration_ok else 'FAIL'}`",
        "",
        "The calibration is deliberately required as a confidence check.  A Cat24 candidate is not considered strong if this same-base method cannot rediscover the already-closed Cat42/CSP programmer.",
        "",
    ]
    emit_family(lines, data, "Calibration: CSP candidates in R2Y driver neighbourhood", CSP, csp_driver)
    emit_family(lines, data, "Cat24 target: YCC candidates in same R2Y driver neighbourhood", YCC, ycc_driver)
    emit_family(lines, data, "Supporting search: YCC-shaped stores near Leica CSP wrapper", YCC, ycc_wrapper_neighbourhood)

    lines += [
        "## Evidence boundary",
        "",
        "A high-completeness YCC candidate in the same low-level driver neighbourhood, especially with a coherent same-base ordered store family and callers into Leica's R2Y wrapper layer, is strong evidence for the YC-convert hardware programmer. CPU setter address/order still does not establish silicon pixel-stage order; that requires vendor/top-level datapath evidence.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
