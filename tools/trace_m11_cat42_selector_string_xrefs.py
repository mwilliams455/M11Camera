#!/usr/bin/env python3
"""Trace Leica's named Category-42 chroma-suppress selector from relocated strings.

The exact M11-P image has an already-established affine mapping for the Leica
R2Y string/data region: runtime_pointer = raw_offset + 0x3EFD2A98 (mod 2^32).
This probe uses four unique strings belonging to
img_macro_drv_r2y_select_chroma_suppress_paraset, finds A32 literal and
MOVW/MOVT references to their relocated addresses, clusters those references by
conventional A32 function entry, and reports local calls/immediates.

Forensic only. It emits addresses/disassembly metadata, never firmware bytes and
never changes renderer semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import defaultdict
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
DATA_BASE = 0x3EFD2A98
MASK32 = 0xFFFFFFFF

TARGETS = {
    "already_loaded": b"(r2y) R2Y CHROMA SUPPRESS already loaded",
    "category_name": b"NO VALID STRING ->  E_IMG_MACRO_DRV_R2Y_CATEGORY_CsCo_R2Y6A  img_macro_drv_r2y_select_chroma_suppress_paraset",
    "dependency": b"Dependency.Iso:%d   Saturation:%d",
    "error1": b"----ERROR-----   img_macro_drv_r2y_select_chroma_suppress_paraset 1",
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def unique_hit(data: bytes, needle: bytes) -> int:
    p = data.find(needle)
    if p < 0 or data.find(needle, p + 1) >= 0:
        raise ValueError(f"target not unique: {needle!r}")
    return p


def is_a32_ldr_pc(w: int) -> bool:
    cond = (w >> 28) & 0xF
    return (
        cond != 0xF
        and ((w >> 26) & 0x3) == 0x1
        and ((w >> 25) & 1) == 0
        and ((w >> 24) & 1) == 1
        and ((w >> 21) & 1) == 0
        and ((w >> 20) & 1) == 1
        and ((w >> 16) & 0xF) == 0xF
    )


def ldr_literal_xrefs(data: bytes, slot: int) -> list[int]:
    out = []
    lo = max(0, slot - 0x1010) & ~3
    hi = min(len(data) - 4, slot + 0x1010)
    for p in range(lo, hi + 1, 4):
        w = u32(data, p)
        if not is_a32_ldr_pc(w):
            continue
        imm = w & 0xFFF
        eff = p + 8 + imm if ((w >> 23) & 1) else p + 8 - imm
        if eff == slot:
            out.append(p)
    return out


def mov_half(w: int):
    # A32 MOVW/MOVT immediate encoding, any condition except NV.
    cond = (w >> 28) & 0xF
    if cond == 0xF:
        return None
    op = w & 0x0FF00000
    if op not in (0x03000000, 0x03400000):
        return None
    rd = (w >> 12) & 0xF
    imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
    return ("movw" if op == 0x03000000 else "movt", rd, imm16)


def movpair_xrefs(data: bytes, value: int) -> list[tuple[int, int]]:
    lo16 = value & 0xFFFF
    hi16 = (value >> 16) & 0xFFFF
    out = []
    for p in range(0, len(data) - 4, 4):
        a = mov_half(u32(data, p))
        if not a or a[0] != "movw" or a[2] != lo16:
            continue
        rd = a[1]
        for q in range(p + 4, min(len(data) - 3, p + 52), 4):
            b = mov_half(u32(data, q))
            if b and b[0] == "movt" and b[1] == rd and b[2] == hi16:
                out.append((p, q))
                break
    return out


def is_push_lr(w: int) -> bool:
    # STMFD/STMDB sp!,{...,lr}; cond ignored, require Rn=sp, W=1, L=0, P=1,U=0.
    return (
        ((w >> 25) & 0x7) == 0x4
        and ((w >> 24) & 1) == 1
        and ((w >> 23) & 1) == 0
        and ((w >> 21) & 1) == 1
        and ((w >> 20) & 1) == 0
        and ((w >> 16) & 0xF) == 13
        and (w & (1 << 14)) != 0
    )


def function_entry(data: bytes, off: int, span: int = 0x900) -> int | None:
    lo = max(0, off - span) & ~3
    for p in range(off & ~3, lo - 1, -4):
        if is_push_lr(u32(data, p)):
            return p
    return None


def bl_target(off: int, w: int) -> int | None:
    if ((w >> 25) & 0x7) != 0x5 or ((w >> 24) & 1) != 1:
        return None
    imm24 = w & 0xFFFFFF
    if imm24 & 0x800000:
        imm24 -= 1 << 24
    return (off + 8 + (imm24 << 2)) & MASK32


def disasm_window(data: bytes, start: int, end: int) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    out = []
    for i in md.disasm(data[start:end], start):
        out.append(f"0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}")
    return out


def printable_near(data: bytes, off: int, radius: int = 0x180) -> list[tuple[int, str]]:
    lo = max(0, off - radius)
    hi = min(len(data), off + radius)
    rx = re.compile(rb"[\x20-\x7e]{8,}")
    return [(lo + m.start(), m.group().decode("ascii", "replace")) for m in rx.finditer(data[lo:hi])]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected SHA {digest}")

    target_rows = []
    refs_by_entry: dict[int | None, list[dict]] = defaultdict(list)
    for name, needle in TARGETS.items():
        raw = unique_hit(data, needle)
        runtime = (raw + DATA_BASE) & MASK32
        pat = struct.pack("<I", runtime)
        slots = []
        p = 0
        while True:
            p = data.find(pat, p)
            if p < 0:
                break
            if (p & 3) == 0:
                slots.append(p)
            p += 1
        lit_refs = []
        for slot in slots:
            for ref in ldr_literal_xrefs(data, slot):
                lit_refs.append((ref, slot))
                refs_by_entry[function_entry(data, ref)].append({"target": name, "kind": "literal", "ref": ref, "slot": slot})
        movrefs = movpair_xrefs(data, runtime)
        for ref, q in movrefs:
            refs_by_entry[function_entry(data, ref)].append({"target": name, "kind": "movpair", "ref": ref, "movt": q})
        target_rows.append((name, raw, runtime, slots, lit_refs, movrefs))

    ranked = sorted(refs_by_entry.items(), key=lambda kv: (-len({r['target'] for r in kv[1]}), -len(kv[1]), kv[0] if kv[0] is not None else 1 << 60))

    lines = [
        "# M11-P Category-42 selector relocated-string trace",
        "",
        f"- exact SHA-256: `{digest}`",
        f"- established Leica R2Y data relocation: `raw + 0x{DATA_BASE:08x}`",
        "",
        "## Target references",
        "",
        "| target | raw | runtime | literal slots | A32 literal refs | MOVW/MOVT refs |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, raw, runtime, slots, lit_refs, movrefs in target_rows:
        lines.append(f"| {name} | `0x{raw:08x}` | `0x{runtime:08x}` | {len(slots)} | {len(lit_refs)} | {len(movrefs)} |")

    lines += ["", "## Function clusters", ""]
    if not ranked:
        lines += ["No direct relocated A32 references found.", ""]
    for idx, (entry, refs) in enumerate(ranked[:16], 1):
        names = sorted({r["target"] for r in refs})
        lines += [
            f"### Candidate {idx}: `{('unknown' if entry is None else f'0x{entry:08x}')}`",
            "",
            f"- distinct selector strings referenced: `{len(names)}/4` — `{names}`",
            f"- total direct references: `{len(refs)}`",
        ]
        for r in refs:
            extra = f" literal=0x{r['slot']:08x}" if r["kind"] == "literal" else f" movt=0x{r['movt']:08x}"
            lines.append(f"- `{r['target']}` via {r['kind']} at `0x{r['ref']:08x}`{extra}")
        if entry is not None:
            # Bounded local disassembly; include calls and obvious small immediates such as category 42.
            end = min(len(data), entry + 0x700)
            ins = disasm_window(data, entry, end)
            bls = []
            imm42 = []
            for p in range(entry, end - 3, 4):
                w = u32(data, p)
                bt = bl_target(p, w)
                if bt is not None:
                    bls.append((p, bt))
                # MOV/MVN/CMP immediate encodings can be complex; use disassembly text as a locator for #0x2a/#42.
            for line in ins:
                low = line.lower()
                if "#0x2a" in low or "#42" in low:
                    imm42.append(line)
            lines += [f"- A32 BL calls in first 0x700 bytes: `{len(bls)}`"]
            for p, bt in bls[:40]:
                lines.append(f"  - `0x{p:08x}` -> `0x{bt:08x}`")
            if imm42:
                lines += ["- immediate 42 candidates:"] + [f"  - `{x}`" for x in imm42[:20]]
            lines += ["- disassembly (bounded):", "```text"] + ins[:220] + ["```"]
        lines.append("")

    lines += ["## Nearby selector-family strings", ""]
    dep_raw = unique_hit(data, TARGETS["dependency"])
    for off, s in printable_near(data, dep_raw, 0x300):
        lines.append(f"- `0x{off:08x}` {s}")

    lines += [
        "",
        "## Evidence boundary",
        "",
        "A function cluster referencing multiple independently relocated selector strings is strong function-identity evidence. Calls and immediates remain control-flow locators until their ABI/data flow is decoded. This probe does not claim CSYKY endpoint semantics and does not modify renderer behavior.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
