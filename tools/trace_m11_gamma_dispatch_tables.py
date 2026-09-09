#!/usr/bin/env python3
"""Decode Leica M11-P gamma-selector A32 dispatch tables exactly.

The exact gamma xref flow contains conditional register-indexed loads into PC.
Capstone renders the following table words as instructions, so this pass treats
them explicitly as data and solves their code-address affine mapping from local
branch destinations inside the same Leica function.  It does not reuse the
separately established data/string affine base.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
START = 0x0157933C
END = 0x01579BF8


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def direct_branch_target(off: int, word: int) -> int | None:
    # A32 B/BL immediate. Calls are rejected below by bit24.
    if (word & 0x0E000000) != 0x0A000000:
        return None
    if word & 0x01000000:  # BL
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return off + 8 + (imm << 2)


def disasm_one(md: Cs, data: bytes, off: int):
    return next(md.disasm(data[off:off+4], off), None)


def local_branch_targets(data: bytes) -> set[int]:
    out = set()
    for off in range(START, END, 4):
        t = direct_branch_target(off, u32(data, off))
        if t is not None and START <= t < END and not (t & 3):
            out.add(t)
    return out


def find_dispatches(data: bytes) -> list[dict]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    out = []
    for off in range(START, END, 4):
        ins = disasm_one(md, data, off)
        if ins is None:
            continue
        if not ins.mnemonic.startswith("ldr"):
            continue
        if not ins.op_str.startswith("pc, [pc,") or "lsl #2" not in ins.op_str:
            continue
        m = re.search(r"\[pc, (r\d+|ip|lr), lsl #2\]", ins.op_str)
        if not m:
            continue
        reg = m.group(1)
        limit = None
        cmp_off = None
        for p in range(off - 4, max(START - 4, off - 0x30), -4):
            prev = disasm_one(md, data, p)
            if prev is None or prev.mnemonic != "cmp":
                continue
            cm = re.fullmatch(rf"{re.escape(reg)}, #(0x[0-9a-f]+|[0-9]+)", prev.op_str)
            if cm:
                limit = int(cm.group(1), 0)
                cmp_off = p
                break
        if limit is None or limit > 31:
            continue
        table = off + 8
        entries = [u32(data, table + i*4) for i in range(limit + 1)]
        out.append({
            "off": off,
            "mnemonic": ins.mnemonic,
            "reg": reg,
            "cmp_off": cmp_off,
            "limit": limit,
            "table": table,
            "entries": entries,
        })
    return out


def infer_bases(entries: list[int], branch_targets: set[int]) -> list[dict]:
    # Any table entry may correspond to any independently visible local basic
    # block target. Test those differences as candidate code affine bases.
    candidates = set()
    for v in entries:
        for t in branch_targets:
            candidates.add((v - t) & 0xFFFFFFFF)

    rows = []
    for base in candidates:
        mapped = [((v - base) & 0xFFFFFFFF) for v in entries]
        in_range = sum(START <= t < END and not (t & 3) for t in mapped)
        branch_hits = sum(t in branch_targets for t in mapped)
        unique_targets = len(set(mapped))
        if in_range < max(2, len(entries) - 1):
            continue
        rows.append({
            "base": base,
            "mapped": mapped,
            "in_range": in_range,
            "branch_hits": branch_hits,
            "unique_targets": unique_targets,
        })
    rows.sort(key=lambda r: (-r["branch_hits"], -r["in_range"], -r["unique_targets"], r["base"]))
    return rows


def snippet(md: Cs, data: bytes, target: int, words: int = 8) -> str:
    if not (START <= target < END):
        return "out-of-range"
    insns = list(md.disasm(data[target:min(END, target + words*4)], target))
    return "; ".join(f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in insns[:words])


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P unpacked SHA-256 {digest}")
    branches = local_branch_targets(data)
    dispatches = find_dispatches(data)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)

    lines = [
        "# M11-P R2A gamma selector dispatch-table decode",
        "",
        f"- SHA-256: `{digest}`",
        f"- candidate raw range: `0x{START:08x}–0x{END:08x}`",
        f"- independently visible local branch destinations: `{len(branches)}`",
        f"- bounded register-indexed PC dispatches: `{len(dispatches)}`",
        "- code-pointer affine bases are solved independently from the data/string affine base.",
        "",
    ]

    for n, d in enumerate(dispatches, 1):
        lines += [
            f"## Dispatch {n} at `0x{d['off']:08x}`",
            "",
            f"- instruction: `{d['mnemonic']} pc, [pc, {d['reg']}, lsl #2]`",
            f"- bound: `cmp {d['reg']}, #{d['limit']}` at `0x{d['cmp_off']:08x}`",
            f"- table raw start: `0x{d['table']:08x}`",
            f"- entry count: `{len(d['entries'])}`",
            "",
            "### Raw table words",
            "",
        ]
        for i, v in enumerate(d["entries"]):
            lines.append(f"- index `{i}`: `0x{v:08x}`")
        lines.append("")

        bases = infer_bases(d["entries"], branches)
        lines += ["### Best code-affine base candidates", ""]
        if not bases:
            lines.append("No base candidate maps enough entries into the exact function range.")
            lines.append("")
            continue
        for row in bases[:12]:
            lines.append(
                f"- base `0x{row['base']:08x}`: local `{row['in_range']}/{len(d['entries'])}`, "
                f"known-branch `{row['branch_hits']}/{len(d['entries'])}`, unique targets `{row['unique_targets']}`"
            )
            lines.append("  - mapped: " + ", ".join(f"`{i}->0x{t:08x}`" for i, t in enumerate(row["mapped"])))
        best = bases[0]
        lines += ["", "### Best-candidate target snippets", ""]
        for i, t in enumerate(best["mapped"]):
            lines.append(f"- index `{i}` -> `0x{t:08x}`: `{snippet(md, data, t)}`")
        lines.append("")

    # Cross-dispatch bases are especially strong: report bases that are top
    # candidates for more than one table.
    base_counts = Counter()
    per_dispatch = []
    for d in dispatches:
        rows = infer_bases(d["entries"], branches)
        strong = {r["base"] for r in rows if r["branch_hits"] >= max(2, len(d["entries"]) // 2)}
        per_dispatch.append(strong)
        base_counts.update(strong)
    lines += ["## Cross-dispatch code-base consistency", ""]
    for base, count in base_counts.most_common(20):
        if count >= 2:
            lines.append(f"- `0x{base:08x}` survives strong mapping in `{count}` dispatches")
    if not any(c >= 2 for c in base_counts.values()):
        lines.append("- no base survives strongly across multiple dispatches")
    lines += [
        "",
        "## Interpretation boundary",
        "",
        "A dispatch mapping is promoted only when the table word, bound, code-affine translation, and mapped local basic block are all internally consistent. This establishes Leica selector structure but does not by itself attach public Milbeaut API names to the cases.",
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
