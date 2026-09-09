#!/usr/bin/env python3
"""Exhaustive sliding exact-window matcher for pinned Milbeaut R2Y objects.

The first matcher tested only prefixes of relocation-free instruction runs.
This pass enumerates every possible 4-word start inside each unmasked run,
checks it against the independently narrowed Leica A32 region, extends each
hit to the longest exact consecutive window, then checks that longest window
against the full firmware for uniqueness.

A candidate-region restriction is used only to discover windows efficiently;
reported global hit counts are always computed over the complete hash-gated
M11-P image.  This remains compiler/source correlation, not runtime semantic
proof.
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
CANDIDATE_START = 0x01578000
CANDIDATE_END = 0x01583000
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


def all_hits(data: bytes, needle: bytes, start: int = 0, end: int | None = None, limit: int = 4096) -> list[int]:
    if not needle:
        return []
    if end is None:
        end = len(data)
    out: list[int] = []
    p = start
    while len(out) < limit:
        p = data.find(needle, p, end)
        if p < 0:
            break
        out.append(p)
        p += 1
    return out


def is_link_sensitive_a32(word: int) -> bool:
    if ((word >> 25) & 0x7) == 0x5:
        return True
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
            raw = sec.data()[start:start + size]
            if len(raw) != size:
                continue
            if shndx not in rel_cache:
                rel_cache[shndx] = relocation_offsets(elf, shndx)
            masks: set[int] = set()
            for roff in rel_cache[shndx]:
                if start <= roff < start + size:
                    masks.add((roff - start) // 4)
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
    return runs


def selected_functions(paths: Iterable[Path]) -> list[Function]:
    out: list[Function] = []
    for path in paths:
        for fn in load_functions(path):
            if fn.name in TARGET_NAMES or "gamma" in fn.name.lower() or "gammma" in fn.name.lower():
                out.append(fn)
    return out


def extend_exact(m11: bytes, fn: Function, obj_word: int, hit: int, run_end: int, cap_words: int = 64) -> int:
    max_words = min(run_end - obj_word, cap_words)
    count = 0
    for k in range(max_words):
        a = fn.data[(obj_word + k) * 4:(obj_word + k + 1) * 4]
        b = m11[hit + k * 4:hit + (k + 1) * 4]
        if len(b) != 4 or a != b:
            break
        count += 1
    return count


def disasm(raw: bytes, base: int, words: int) -> str:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except Exception:
        return "capstone unavailable"
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    return "; ".join(
        f"{i.address:#x}:{i.mnemonic} {i.op_str}"
        for i in list(md.disasm(raw[:words * 4], base))[:min(words, 16)]
    )


def sliding_matches(m11: bytes, fn: Function) -> list[dict]:
    rows: list[dict] = []
    for run_start, run_end in unmasked_runs(fn, 4):
        for obj_word in range(run_start, run_end - 3):
            needle4 = fn.data[obj_word * 4:(obj_word + 4) * 4]
            candidate_hits = all_hits(
                m11, needle4,
                start=CANDIDATE_START,
                end=min(CANDIDATE_END, len(m11)),
                limit=256,
            )
            for hit in candidate_hits:
                words = extend_exact(m11, fn, obj_word, hit, run_end)
                if words < 4:
                    continue
                longest = fn.data[obj_word * 4:(obj_word + words) * 4]
                globals_ = all_hits(m11, longest, 0, len(m11), 256)
                rows.append({
                    "obj_word": obj_word,
                    "words": words,
                    "candidate_hit": hit,
                    "global_hits": globals_,
                    "run": (run_start, run_end),
                    "disasm": disasm(longest, obj_word * 4, words),
                })
    # Deduplicate identical object start/candidate pair, then greedily prefer
    # longer independent windows that do not overlap in either object or M11.
    uniq: dict[tuple[int, int], dict] = {}
    for row in rows:
        key = (row["obj_word"], row["candidate_hit"])
        prev = uniq.get(key)
        if prev is None or row["words"] > prev["words"]:
            uniq[key] = row
    ordered = sorted(
        uniq.values(),
        key=lambda r: (-r["words"], len(r["global_hits"]), r["candidate_hit"], r["obj_word"]),
    )
    independent: list[dict] = []
    for row in ordered:
        os, oe = row["obj_word"], row["obj_word"] + row["words"]
        ms, me = row["candidate_hit"], row["candidate_hit"] + row["words"] * 4
        overlaps = False
        for kept in independent:
            kos, koe = kept["obj_word"], kept["obj_word"] + kept["words"]
            kms, kme = kept["candidate_hit"], kept["candidate_hit"] + kept["words"] * 4
            if not (oe <= kos or os >= koe) or not (me <= kms or ms >= kme):
                overlaps = True
                break
        if not overlaps:
            independent.append(row)
    return independent


def report(m11: bytes, object_paths: Iterable[Path]) -> str:
    digest = hashlib.sha256(m11).hexdigest()
    if digest != EXPECTED_M11_SHA:
        raise ValueError(f"unexpected M11 unpacked SHA-256 {digest}")
    funcs = selected_functions(object_paths)
    lines = [
        "# M11-P sliding exact-GCC Milbeaut gamma fingerprint report",
        "",
        f"- exact M11-P unpacked SHA-256: `{digest}`",
        "- public reference: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`",
        "- compiler: ARM Embedded GCC 4.9.3 20150529 / Cortex-A7 / A32",
        f"- discovery region: `0x{CANDIDATE_START:08x}–0x{CANDIDATE_END:08x}`",
        "- discovery method: every 4-word start inside every relocation/branch-free run; each candidate hit extended to the longest exact consecutive window; longest needle then searched globally",
        "",
    ]
    if not funcs:
        lines += ["No selected gamma functions found.", ""]
        return "\n".join(lines)
    for fn in funcs:
        rows = sliding_matches(m11, fn)
        lines += [
            f"## `{fn.name}`",
            "",
            f"- object: `{fn.obj.name}`",
            f"- size: `{fn.size}` bytes",
            f"- unmasked runs >=4 words: `{len(unmasked_runs(fn, 4))}`",
            f"- independent candidate-region exact windows: `{len(rows)}`",
        ]
        for row in rows[:24]:
            lines.append(
                f"- object word `{row['obj_word']}` -> M11 `0x{row['candidate_hit']:08x}`: "
                f"`{row['words']}` exact words; global hit count `{len(row['global_hits'])}`"
            )
            if row["global_hits"]:
                lines.append("  - global offsets: " + ", ".join(f"`0x{x:08x}`" for x in row["global_hits"][:24]))
            lines.append(f"  - reference disassembly: `{row['disasm']}`")
        lines.append("")
    lines += [
        "## Interpretation boundary",
        "",
        "A candidate-region exact window is compiler/source correlation evidence because the region was independently narrowed by Leica diagnostic xrefs. Global uniqueness is reported separately. Multiple non-overlapping exact windows from one public function converging on one Leica function region are substantially stronger than a single short window, but runtime table selection/control semantics still require Leica callsite evidence.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("m11", type=Path)
    ap.add_argument("objects", type=Path, nargs="+")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    text = report(args.m11.read_bytes(), args.objects)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
