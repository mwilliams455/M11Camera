#!/usr/bin/env python3
"""Trace Leica M11-P BB06 packet tags and the common submit routine.

Primary target: A32 BL calls to raw code offset 0x015765b4, which is called by
the exact gamma-selector candidate after it builds a local record beginning
with 0xBB060015 / 0xBB060017.  This pass answers what the BB06 low-word
namespace means by surveying the same submit routine across the exact firmware.

Only derived offsets/disassembly/constant metadata are emitted.  No Leica
firmware bytes are redistributed.
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
SUBMIT = 0x015765B4
DATA_AFFINE_BASE = 0x3EFD2A98
SCAN_START = 0x01000000
SCAN_END = 0x02000000


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    if (word & 0x0F000000) != 0x0B000000:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def mov_imm16(word: int) -> tuple[str, int, int] | None:
    op = word & 0x0FF00000
    if op not in (0x03000000, 0x03400000):
        return None
    kind = "movw" if op == 0x03000000 else "movt"
    rd = (word >> 12) & 0xF
    imm = ((word >> 4) & 0xF000) | (word & 0xFFF)
    return kind, rd, imm


def is_ldr_literal(word: int) -> bool:
    return (word & 0x0F7F0000) == 0x051F0000


def literal_value(data: bytes, off: int, word: int) -> tuple[int, int, int] | None:
    if not is_ldr_literal(word):
        return None
    imm = word & 0xFFF
    pool = off + 8 + (imm if word & 0x00800000 else -imm)
    if pool < 0 or pool + 4 > len(data) or pool & 3:
        return None
    return pool, u32(data, pool), (word >> 12) & 0xF


def printable_at(data: bytes, off: int, max_len: int = 120) -> str | None:
    if off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end <= off:
        return None
    raw = data[off:end]
    if len(raw) < 5:
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 and c not in "\r\n\t" for c in s):
        return None
    if any(ord(c) >= 0x7f for c in s):
        return None
    return s.replace("\n", "\\n").replace("\r", "\\r")


def data_annotation(data: bytes, value: int) -> str | None:
    raw = (value - DATA_AFFINE_BASE) & 0xFFFFFFFF
    if raw >= len(data):
        return None
    s = printable_at(data, raw)
    if s:
        return f"raw=0x{raw:08x} string={s!r}"
    return None


def find_submit_calls(data: bytes) -> list[int]:
    end = min(len(data) - 4, SCAN_END)
    hits = []
    for off in range(SCAN_START & ~3, end & ~3, 4):
        if bl_target(off, u32(data, off)) == SUBMIT:
            hits.append(off)
    return hits


def find_bb06_pairs(data: bytes, start: int, end: int) -> list[dict]:
    out = []
    end = min(end, len(data) - 4)
    for off in range(max(0, start) & ~3, end & ~3, 4):
        d = mov_imm16(u32(data, off))
        if d is None or d[0] != "movw":
            continue
        _, rd, lo = d
        for p in range(off + 4, min(end, off + 0x28) + 1, 4):
            d2 = mov_imm16(u32(data, p))
            if d2 is None:
                continue
            if d2[0] == "movt" and d2[1] == rd:
                value = lo | (d2[2] << 16)
                if (value >> 16) == 0xBB06:
                    out.append({"movw": off, "movt": p, "reg": rd, "value": value, "low": lo})
                break
    return out


def nearest_prologue(data: bytes, center: int, radius: int = 0x1000) -> int | None:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    start = max(SCAN_START, center - radius) & ~3
    best = None
    for off in range(start, center + 1, 4):
        ins = next(md.disasm(data[off:off+4], off), None)
        if ins is None:
            continue
        if ins.mnemonic in ("push", "stmdb") and "lr" in ins.op_str and ("sp" in ins.op_str or ins.mnemonic == "push"):
            best = off
    return best


def function_end_guess(data: bytes, start: int, max_len: int = 0x1800) -> int:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    end = min(len(data), start + max_len)
    seen = 0
    for off in range(start, end, 4):
        ins = next(md.disasm(data[off:off+4], off), None)
        if ins is None:
            continue
        seen += 1
        if seen > 3 and ins.mnemonic in ("pop", "ldmia") and "pc" in ins.op_str:
            return off + 4
        if seen > 3 and ins.mnemonic == "bx" and ins.op_str == "lr":
            return off + 4
    return end


def function_strings(data: bytes, start: int, end: int) -> list[tuple[int, int, str]]:
    rows = []
    for off in range(start & ~3, min(end, len(data)-4) & ~3, 4):
        lit = literal_value(data, off, u32(data, off))
        if lit is None:
            continue
        _, value, _ = lit
        ann = data_annotation(data, value)
        if ann:
            rows.append((off, value, ann))
    # dedupe same annotation within one function while preserving earliest use
    seen = set()
    out = []
    for row in rows:
        key = row[2]
        if key not in seen:
            out.append(row)
            seen.add(key)
    return out


def window_disasm(data: bytes, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    out = []
    for ins in md.disasm(data[max(0,start):min(len(data),end)], max(0,start)):
        note = ""
        off = ins.address
        if off + 4 <= len(data) and not (off & 3):
            word = u32(data, off)
            bt = bl_target(off, word)
            if bt is not None:
                note += f" ; BL=0x{bt:08x}"
            lit = literal_value(data, off, word)
            if lit is not None:
                pool, value, rt = lit
                ann = data_annotation(data, value)
                if ann:
                    note += f" ; literal r{rt}=0x{value:08x} {ann}"
        out.append(f"0x{off:08x}: {ins.mnemonic} {ins.op_str}{note}".rstrip())
    return out


def submit_target_summary(data: bytes) -> list[str]:
    # Derive a conservative local body window from target prologue to first
    # obvious return, then list direct callees and useful constants.
    end = function_end_guess(data, SUBMIT, 0x600)
    calls = Counter()
    bb = find_bb06_pairs(data, SUBMIT, end)
    for off in range(SUBMIT, end, 4):
        bt = bl_target(off, u32(data, off))
        if bt is not None:
            calls[bt] += 1
    lines = [
        f"- target body guess: `0x{SUBMIT:08x}–0x{end:08x}` (`0x{end-SUBMIT:x}` bytes)",
        f"- distinct direct callees: `{len(calls)}`",
        f"- BB06 constants constructed inside target: `{len(bb)}`",
    ]
    for target, n in calls.most_common():
        lines.append(f"  - `0x{target:08x}`: `{n}` call(s)")
    lines += ["", "```text"]
    lines.extend(window_disasm(data, SUBMIT, min(end, SUBMIT + 0x280)))
    lines.append("```")
    return lines


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P unpacked SHA-256 {digest}")

    calls = find_submit_calls(data)
    groups: dict[int, list[int]] = defaultdict(list)
    meta = {}
    for call in calls:
        pro = nearest_prologue(data, call)
        if pro is None:
            pro = call & ~0xFF
        groups[pro].append(call)
        if pro not in meta:
            end = function_end_guess(data, pro)
            meta[pro] = {
                "end": end,
                "bb06": find_bb06_pairs(data, pro, end),
                "strings": function_strings(data, pro, end),
            }

    global_bb = find_bb06_pairs(data, SCAN_START, min(SCAN_END, len(data)))
    low_counts = Counter(row["low"] for row in global_bb)

    lines = [
        "# M11-P R2A BB06 packet / common-submit trace",
        "",
        f"- exact SHA-256: `{digest}`",
        f"- common submit target: `0x{SUBMIT:08x}`",
        f"- direct A32 callers in scan range: `{len(calls)}` across `{len(groups)}` prologue families",
        f"- all `0xBB06xxxx` MOVW/MOVT constructions in code scan: `{len(global_bb)}`",
        "- BB06 low words are reported as hexadecimal packet/tag IDs. They are **not** equated to decimal R2YS Category numbers.",
        "",
        "## Common submit target body",
        "",
    ]
    lines.extend(submit_target_summary(data))
    lines += ["", "## BB06 tag frequency in code", ""]
    for low, n in sorted(low_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- `0x{low:04x}` / full `0xBB06{low:04X}`: `{n}` construction(s)")

    lines += ["", "## Submit caller families", ""]
    for pro in sorted(groups):
        info = meta[pro]
        end = info["end"]
        lines += [
            f"### prologue candidate `0x{pro:08x}`",
            "",
            f"- body guess: `0x{pro:08x}–0x{end:08x}`",
            "- submit callsite(s): " + ", ".join(f"`0x{x:08x}`" for x in groups[pro]),
        ]
        if info["bb06"]:
            lines.append("- BB06 tag(s): " + ", ".join(
                f"`0x{r['value']:08x}` at `0x{r['movw']:08x}`/`0x{r['movt']:08x}` r{r['reg']}"
                for r in info["bb06"]
            ))
        else:
            lines.append("- BB06 tag(s): none found in body guess")
        if info["strings"]:
            lines.append("- exact data-affine printable literal(s):")
            for off, value, ann in info["strings"][:12]:
                lines.append(f"  - `0x{off:08x}` -> `0x{value:08x}` {ann}")
        lines += ["", "```text"]
        for call in groups[pro]:
            lines.extend(window_disasm(data, max(pro, call - 0x70), min(end, call + 0x24)))
            lines.append("---")
        lines += ["```", ""]

    lines += [
        "## Interpretation boundary",
        "",
        "A BB06 tag association is promoted only when the tag construction and call to the same common submit routine occur in one bounded Leica function family. This trace can establish packet/tag namespace relationships, but R2YS Category identities require independent descriptor/consumer evidence.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(report(a.unpacked.read_bytes()))
    print(a.output)


if __name__ == "__main__":
    main()
