#!/usr/bin/env python3
"""Trace the exact Leica M11-P gamma-selector candidate control flow.

This is Leica-primary forensic analysis.  It operates only on the exact
hash-gated unpacked 2.6.1 image and emits derived A32 disassembly/control-flow
metadata.  It does not assign public Milbeaut names to Leica functions.

The candidate ranges come from the exact full-string xref pass:
  0x0157933c..0x01579bf8  -- 20 direct `gamma_loaded` xrefs
  0x01579bf8..0x01579cbc  -- 2 direct `gamma_invalid` xrefs

The affine base 0x3efd2a98 is used only for already-reconciled data/string
virtual pointers.  It is not assumed to be the code mapping.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
DATA_AFFINE_BASE = 0x3EFD2A98
LOGGER = 0x01679B58
RANGES = [
    ("gamma_loaded_family", 0x0157933C, 0x01579BF8),
    ("gamma_invalid_family", 0x01579BF8, 0x01579CBC),
]
KNOWN_RAW_STRINGS = {
    "gamma_loaded": 0x02788848,
    "gamma_invalid": 0x02788868,
    "gamma_err2": 0x027888A4,
    "gamma_err3": 0x027888DC,
    "gamma_rgbyb": 0x02788914,
}
KNOWN_VIRTUAL_STRINGS = {
    name: (DATA_AFFINE_BASE + raw) & 0xFFFFFFFF
    for name, raw in KNOWN_RAW_STRINGS.items()
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    if (word & 0x0F000000) != 0x0B000000:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def b_target(off: int, word: int) -> int | None:
    if (word & 0x0E000000) != 0x0A000000:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def is_ldr_literal(word: int) -> bool:
    return (word & 0x0F7F0000) == 0x051F0000


def ldr_literal(data: bytes, off: int, word: int) -> tuple[int, int, int] | None:
    if not is_ldr_literal(word):
        return None
    imm = word & 0xFFF
    pool = off + 8 + (imm if word & 0x00800000 else -imm)
    if pool < 0 or pool + 4 > len(data) or pool & 3:
        return None
    rt = (word >> 12) & 0xF
    return pool, u32(data, pool), rt


def mov_imm16(word: int) -> tuple[str, int, int] | None:
    op = word & 0x0FF00000
    if op not in (0x03000000, 0x03400000):
        return None
    kind = "movw" if op == 0x03000000 else "movt"
    rd = (word >> 12) & 0xF
    imm = ((word >> 4) & 0xF000) | (word & 0xFFF)
    return kind, rd, imm


def printable_at(data: bytes, off: int, max_len: int = 120) -> str | None:
    if off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end < 0 or end == off:
        return None
    raw = data[off:end]
    if len(raw) < 4:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in text) != len(text):
        return None
    return text.replace("\n", "\\n").replace("\r", "\\r")


def virtual_data_annotation(data: bytes, value: int) -> str | None:
    raw = (value - DATA_AFFINE_BASE) & 0xFFFFFFFF
    if raw >= len(data):
        return None
    text = printable_at(data, raw)
    if text:
        return f"data-vaddr->raw 0x{raw:08x} string={text!r}"
    return f"data-vaddr->raw 0x{raw:08x}"


def known_string_name(value: int) -> str | None:
    for name, addr in KNOWN_VIRTUAL_STRINGS.items():
        if value == addr:
            return name
    return None


def movw_movt_pairs(data: bytes, start: int, end: int) -> list[dict]:
    out: list[dict] = []
    end_aligned = min((len(data) - 4) & ~3, end)
    for off in range(start & ~3, end_aligned, 4):
        d = mov_imm16(u32(data, off))
        if d is None or d[0] != "movw":
            continue
        _, rd, lo = d
        for p in range(off + 4, min(end_aligned, off + 0x24) + 1, 4):
            d2 = mov_imm16(u32(data, p))
            if d2 is None:
                continue
            if d2[0] == "movt" and d2[1] == rd:
                value = lo | (d2[2] << 16)
                out.append({"movw": off, "movt": p, "rd": rd, "value": value})
                break
    return out


def decode_jump_tables(data: bytes, start: int, end: int) -> list[dict]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[start:end], start))
    out: list[dict] = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic != "ldr" or not ins.op_str.startswith("pc, [pc,") or "lsl #2" not in ins.op_str:
            continue
        m = re.search(r"\[pc, (r\d+), lsl #2\]", ins.op_str)
        if not m:
            continue
        reg = m.group(1)
        limit = None
        for prev in reversed(insns[max(0, idx - 6):idx]):
            cm = re.fullmatch(rf"{re.escape(reg)}, #0x?([0-9a-f]+)", prev.op_str)
            if prev.mnemonic == "cmp" and cm:
                limit = int(cm.group(1), 16)
                break
            cm2 = re.fullmatch(rf"{re.escape(reg)}, #(\d+)", prev.op_str)
            if prev.mnemonic == "cmp" and cm2:
                limit = int(cm2.group(1), 10)
                break
        n = (limit + 1) if limit is not None and limit <= 32 else 8
        table = ins.address + 8
        entries = []
        for i in range(n):
            p = table + i * 4
            if p + 4 > len(data):
                break
            value = u32(data, p)
            row = {"index": i, "pool": p, "value": value}
            if start <= value < end:
                row["raw_target"] = value
            via_data = (value - DATA_AFFINE_BASE) & 0xFFFFFFFF
            if start <= via_data < end:
                row["data_affine_target"] = via_data
            entries.append(row)
        out.append({
            "insn": ins.address,
            "reg": reg,
            "limit": limit,
            "table": table,
            "entries": entries,
        })
    return out


def candidate_disassembly(data: bytes, label: str, start: int, end: int) -> tuple[list[str], dict]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    callsites: defaultdict[int, list[int]] = defaultdict(list)
    local_branches: defaultdict[int, list[int]] = defaultdict(list)
    literals: list[dict] = []
    compare_sites: list[tuple[int, str]] = []
    lines: list[str] = []

    for ins in md.disasm(data[start:end], start):
        off = ins.address
        note: list[str] = []
        if off + 4 <= len(data) and not (off & 3):
            word = u32(data, off)
            bt = bl_target(off, word)
            if bt is not None:
                callsites[bt].append(off)
                note.append(f"BL=0x{bt:08x}" + (" LOGGER" if bt == LOGGER else ""))
            else:
                br = b_target(off, word)
                if br is not None and start <= br < end:
                    local_branches[br].append(off)
                    note.append(f"local-branch=0x{br:08x}")
            lit = ldr_literal(data, off, word)
            if lit is not None:
                pool, value, rt = lit
                row = {"off": off, "pool": pool, "value": value, "rt": rt}
                literals.append(row)
                ks = known_string_name(value)
                if ks:
                    note.append(f"EXACT_STRING={ks} pool=0x{pool:08x}")
                else:
                    ann = virtual_data_annotation(data, value)
                    if ann:
                        note.append(f"literal=0x{value:08x} {ann}")
                    else:
                        note.append(f"literal=0x{value:08x} pool=0x{pool:08x}")
        if ins.mnemonic == "cmp" and re.search(r", #(?:0x)?[0-9a-f]+$", ins.op_str):
            compare_sites.append((off, ins.op_str))
        suffix = (" ; " + " ; ".join(note)) if note else ""
        lines.append(f"0x{off:08x}: {ins.mnemonic} {ins.op_str}{suffix}".rstrip())

    info = {
        "label": label,
        "start": start,
        "end": end,
        "callsites": callsites,
        "local_branches": local_branches,
        "literals": literals,
        "compare_sites": compare_sites,
        "movpairs": movw_movt_pairs(data, start, end),
        "jump_tables": decode_jump_tables(data, start, end),
    }
    return lines, info


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P unpacked SHA-256: {digest}")

    lines = [
        "# M11-P R2A exact gamma candidate control-flow trace",
        "",
        f"- SHA-256: `{digest}`",
        f"- reconciled data/string affine base: `0x{DATA_AFFINE_BASE:08x}`",
        f"- shared diagnostic logger: `0x{LOGGER:08x}`",
        "- Function names remain provisional; ranges are identified only by exact gamma diagnostic xref ownership.",
        "",
    ]

    all_info = []
    disasm_by_label = {}
    for label, start, end in RANGES:
        dlines, info = candidate_disassembly(data, label, start, end)
        all_info.append(info)
        disasm_by_label[label] = dlines

        lines += [
            f"## `{label}` `0x{start:08x}–0x{end:08x}`",
            "",
            f"- span: `{end-start}` bytes (`0x{end-start:x}`)",
            f"- distinct direct BL targets: `{len(info['callsites'])}`",
            f"- PC-relative literal loads: `{len(info['literals'])}`",
            f"- MOVW/MOVT address constructions: `{len(info['movpairs'])}`",
            f"- bounded register-indexed PC jump tables: `{len(info['jump_tables'])}`",
            "",
            "### Direct call targets",
            "",
        ]
        for target, sites in sorted(info["callsites"].items(), key=lambda kv: (-len(kv[1]), kv[0])):
            extra = " — shared diagnostic logger" if target == LOGGER else ""
            lines.append(
                f"- `0x{target:08x}`: `{len(sites)}` call(s) at "
                + ", ".join(f"`0x{x:08x}`" for x in sites)
                + extra
            )
        lines.append("")

        lines += ["### Exact gamma-string literal loads", ""]
        string_rows = [x for x in info["literals"] if known_string_name(x["value"])]
        if not string_rows:
            lines.append("- none")
        for row in string_rows:
            lines.append(
                f"- `0x{row['off']:08x}` -> `{known_string_name(row['value'])}` "
                f"via pool `0x{row['pool']:08x}`, r{row['rt']}"
            )
        lines.append("")

        lines += ["### MOVW/MOVT constructed addresses", ""]
        for row in info["movpairs"]:
            ann = virtual_data_annotation(data, row["value"])
            suffix = f" — {ann}" if ann else ""
            lines.append(
                f"- `0x{row['movw']:08x}`/`0x{row['movt']:08x}` r{row['rd']} = "
                f"`0x{row['value']:08x}`{suffix}"
            )
        if not info["movpairs"]:
            lines.append("- none")
        lines.append("")

        lines += ["### Register-indexed PC jump tables", ""]
        if not info["jump_tables"]:
            lines.append("- none")
        for jt in info["jump_tables"]:
            lim = "unknown" if jt["limit"] is None else str(jt["limit"])
            lines.append(
                f"- dispatch `0x{jt['insn']:08x}` using {jt['reg']}, prior bound `{lim}`, "
                f"table raw `0x{jt['table']:08x}`"
            )
            for e in jt["entries"]:
                suffix = ""
                if "raw_target" in e:
                    suffix += f" raw-target=0x{e['raw_target']:08x}"
                if "data_affine_target" in e:
                    suffix += f" data-affine-target=0x{e['data_affine_target']:08x}"
                lines.append(
                    f"  - index `{e['index']}` pool `0x{e['pool']:08x}` word `0x{e['value']:08x}`{suffix}"
                )
        lines.append("")

        lines += ["### Small-immediate compare sites", ""]
        for off, ops in info["compare_sites"]:
            lines.append(f"- `0x{off:08x}`: `cmp {ops}`")
        lines.append("")

    lines += ["## Full derived disassembly", ""]
    for label, start, end in RANGES:
        lines += [f"### `{label}`", "", "```text"]
        lines.extend(disasm_by_label[label])
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "This report establishes exact Leica control-flow facts for the gamma-diagnostic code family. It does not infer that a Leica function is identical to a public Milbeaut routine. Register/table semantics should be promoted only when compiler correlation and/or Leica-side call/register evidence independently converge.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report(args.unpacked.read_bytes()))
    print(args.output)


if __name__ == "__main__":
    main()
