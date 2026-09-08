#!/usr/bin/env python3
"""Match exact-GCC public Milbeaut ARM object fingerprints against M11-P firmware.

This is a forensic correlation helper. The public source is external generic
Milbeaut evidence; M11-P 2.6.1 remains the primary target. ELF relocation words
and link-sensitive ARM branch immediates are excluded from exact fingerprints.
The report emits only derived instruction metadata and target offsets, never
Leica firmware bytes or redistributable public object files.

Compile-only compatibility headers are supplied separately and do not alter
this matcher or the public R2Y processing implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from elftools.elf.elffile import ELFFile

EXPECTED_M11_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
TARGET_NAMES = {
    "im_r2y_set_gamma_table",
    "im_r2y_ctrl2_gamma",
    "im_r2y_ctrl2_set_gamma_tbl_access_enable",
    "im_r2y_ctrl2_set_gamma_yb_tbl_access_enable",
    "imR2ySetRdmaValGammmaDiffTable",
    "imR2ySetRdmaValGammmaFullTable",
    "imR2ySetRdmaValGammaCtrl",
}


@dataclass
class Function:
    obj: Path
    name: str
    section_name: str
    start: int
    size: int
    data: bytes
    masked_words: set[int]


def all_hits(data: bytes, needle: bytes, limit: int = 256) -> list[int]:
    if not needle:
        return []
    out: list[int] = []
    p = 0
    while len(out) < limit:
        p = data.find(needle, p)
        if p < 0:
            break
        out.append(p)
        p += 1
    return out


def is_link_sensitive_a32(word: int) -> bool:
    # B/BL immediate: link target changes with final placement.
    if ((word >> 25) & 0x7) == 0x5:
        return True
    # BLX immediate encoding, cond=1111 and 101H imm24.
    if (word & 0xFE000000) == 0xFA000000:
        return True
    return False


def relocation_offsets(elf: ELFFile, target_index: int) -> set[int]:
    out: set[int] = set()
    for sec in elf.iter_sections():
        if sec["sh_type"] not in ("SHT_REL", "SHT_RELA"):
            continue
        if int(sec["sh_info"]) != target_index:
            continue
        for rel in sec.iter_relocations():
            out.add(int(rel["r_offset"]))
    return out


def load_functions(path: Path) -> list[Function]:
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError(f"{path}: no .symtab")
        sec_by_index = {i: s for i, s in enumerate(elf.iter_sections())}
        rel_cache: dict[int, set[int]] = {}
        funcs: list[Function] = []
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            name = sym.name
            size = int(sym["st_size"])
            shndx = sym["st_shndx"]
            if not isinstance(shndx, int) or size < 16:
                continue
            sec = sec_by_index.get(shndx)
            if sec is None or not sec.name.startswith(".text"):
                continue
            start = int(sym["st_value"])
            raw = sec.data()[start : start + size]
            if len(raw) != size:
                continue
            if shndx not in rel_cache:
                rel_cache[shndx] = relocation_offsets(elf, shndx)
            masks: set[int] = set()
            for roff in rel_cache[shndx]:
                if start <= roff < start + size:
                    masks.add((roff - start) // 4)
            # Also suppress branch immediates even when the assembler resolved
            # an intra-object target without a relocation.
            for i in range(0, len(raw) - 3, 4):
                word = struct.unpack_from("<I", raw, i)[0]
                if is_link_sensitive_a32(word):
                    masks.add(i // 4)
            funcs.append(Function(path, name, sec.name, start, size, raw, masks))
        return funcs


def unmasked_runs(fn: Function, min_words: int = 4) -> list[tuple[int, int]]:
    nwords = len(fn.data) // 4
    runs: list[tuple[int, int]] = []
    s: int | None = None
    for i in range(nwords + 1):
        blocked = i == nwords or i in fn.masked_words
        if not blocked and s is None:
            s = i
        if blocked and s is not None:
            if i - s >= min_words:
                runs.append((s, i))
            s = None
    runs.sort(key=lambda r: (-(r[1] - r[0]), r[0]))
    return runs


def disasm_words(raw: bytes, base: int = 0, max_ins: int = 24) -> str:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except Exception:
        return "capstone unavailable"
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    return "; ".join(
        f"{i.address:#x}:{i.mnemonic} {i.op_str}"
        for i in list(md.disasm(raw, base))[:max_ins]
    )


def exact_run_matches(m11: bytes, fn: Function) -> list[dict]:
    rows: list[dict] = []
    for s, e in unmasked_runs(fn, 4)[:16]:
        raw = fn.data[s * 4 : e * 4]
        # Search longest run first; also search capped prefixes so a long run can
        # still provide evidence if a few compiler-local instructions differ.
        lengths = sorted(set([e - s, min(e - s, 16), min(e - s, 12), min(e - s, 8), 6, 5, 4]), reverse=True)
        for words in lengths:
            if words < 4 or words > e - s:
                continue
            needle = raw[: words * 4]
            hits = all_hits(m11, needle, 64)
            if hits:
                rows.append({
                    "object_word": s,
                    "words": words,
                    "hits": hits,
                    "disasm": disasm_words(needle, s * 4, min(words, 16)),
                })
                break
    rows.sort(key=lambda x: (-x["words"], len(x["hits"]), x["object_word"]))
    return rows


def opcode_shape(word: int) -> int:
    """Coarse A32 opcode class with immediates stripped for fuzzy windows."""
    cond = (word >> 28) & 0xF
    # Ignore condition code to tolerate compiler scheduling/predication changes.
    w = word & 0x0FFFFFFF
    if ((word >> 25) & 0x7) == 0x5:  # B/BL
        return 0xB0000000 | ((word >> 24) & 1)
    if (word & 0x0C000000) == 0x04000000:  # single data transfer
        # Preserve I/P/U/B/W/L and Rn/Rd, remove offset.
        return 0x40000000 | (w & 0x03FF0000)
    if (word & 0x0C000000) == 0x00000000:  # data processing/misc
        # Preserve opcode/S/Rn/Rd and register-vs-immediate selector.
        return 0x10000000 | (w & 0x03FFF000)
    return 0x80000000 | (w & 0x0FF00000)


def fuzzy_anchor(fn: Function) -> list[int]:
    """Return a compact shape sequence from the first usable code words."""
    out: list[int] = []
    for i in range(len(fn.data) // 4):
        if i in fn.masked_words:
            continue
        w = struct.unpack_from("<I", fn.data, i * 4)[0]
        out.append(opcode_shape(w))
        if len(out) >= 12:
            break
    return out


def report(m11: bytes, object_paths: Iterable[Path]) -> str:
    lines = [
        "# M11-P exact-GCC Milbeaut object fingerprint report",
        "",
        f"- exact M11-P unpacked SHA-256: `{hashlib.sha256(m11).hexdigest()}`",
        "- public reference: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`",
        "- compiler intent: ARM Embedded GCC 4.9.3 20150529 / Cortex-A7 / A32",
        "",
    ]
    all_funcs: list[Function] = []
    for p in object_paths:
        funcs = load_functions(p)
        all_funcs.extend(funcs)
        lines += [f"## `{p.name}`", "", f"- function symbols: `{len(funcs)}`", ""]
        for fn in funcs:
            if fn.name in TARGET_NAMES or "gamma" in fn.name.lower():
                lines.append(f"- `{fn.name}` size `{fn.size}` section `{fn.section_name}` masked/link-sensitive words `{len(fn.masked_words)}`")
        lines.append("")

    selected = [f for f in all_funcs if f.name in TARGET_NAMES or "gamma" in f.name.lower()]
    lines += ["## Exact relocation-free instruction windows", ""]
    if not selected:
        lines += ["No gamma-related function symbols were found.", ""]
    for fn in selected:
        rows = exact_run_matches(m11, fn)
        lines += [f"### `{fn.name}`", "", f"- object: `{fn.obj.name}`", f"- size: `{fn.size}`", f"- usable unmasked runs >=4 words: `{len(unmasked_runs(fn,4))}`", f"- exact matching runs: `{len(rows)}`"]
        for row in rows[:12]:
            lines.append(f"- object word `{row['object_word']}` length `{row['words']}` words => M11 hit count `{len(row['hits'])}`")
            lines.append("  - M11 offsets: " + ", ".join(f"`0x{x:08x}`" for x in row["hits"][:16]))
            lines.append(f"  - reference disassembly: `{row['disasm']}`")
        shape = fuzzy_anchor(fn)
        lines.append(f"- 12-word coarse opcode-shape anchor: `{' '.join(f'{x:08x}' for x in shape)}`")
        lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "An exact relocation-free window match is strong compiler/source correlation, especially when multiple independent windows from the same function converge on one M11 region. A fuzzy opcode-shape anchor is diagnostic only and is not by itself a function identification. Public Milbeaut code does not establish Leica runtime table selection; Leica callsite/register evidence is still required before renderer changes.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("m11", type=Path)
    ap.add_argument("objects", type=Path, nargs="+")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    m11 = args.m11.read_bytes()
    digest = hashlib.sha256(m11).hexdigest()
    if digest != EXPECTED_M11_SHA:
        raise ValueError(f"unexpected M11 unpacked SHA-256 {digest}")
    text = report(m11, args.objects)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
