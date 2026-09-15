#!/usr/bin/env python3
"""Trace M11-P still R2Y buffer/dataflow toward the downstream still path.

This is deliberately a bounded static-taint probe around the already-closed
still B2B/R2Y job, its callers, and its major callees.  It reports argument
setup, structure-like memory offsets, and call boundaries; it does not claim a
JPEG handoff unless the compiled dataflow actually supports one.

No proprietary firmware bytes are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

JOB = 0x017B9BCC
PARENT = 0x017B5A84
ORCH = 0x017C8838
IMPORTANT_CALLEES = {0x0174C6D8, 0x0176B168, 0x016766B8}

ARG_REGS = {"r0", "r1", "r2", "r3"}
TRACKED_REGS = {f"r{x}" for x in range(12)} | {"sp", "fp", "lr"}
DEF_MNEMONICS = {
    "mov", "movs", "movw", "movt", "mvn",
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh",
    "add", "adds", "sub", "subs", "rsb", "rsbs",
    "orr", "orrs", "eor", "eors", "and", "ands", "bic", "bics",
    "lsl", "lsls", "lsr", "lsrs", "asr", "asrs",
    "adr", "ubfx", "sbfx", "uxtb", "uxth", "sxtb", "sxth",
}


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def bl_target(off: int, word: int) -> int | None:
    # ARM-state BL immediate. Existing project anchors are ARM state.
    if ((word >> 28) & 0xF) == 0xF or ((word >> 24) & 0xF) != 0xB:
        return None
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (off + 8 + (imm << 2)) & 0xFFFFFFFF


def md() -> Cs:
    c = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    c.detail = True
    c.skipdata = True
    return c


def fmt(i) -> str:
    return f"0x{i.address:08X}: {i.mnemonic} {i.op_str}".rstrip()


def function(c: Cs, data: bytes, entry: int, max_len: int = 0x14000):
    out = []
    for i in c.disasm(data[entry:min(len(data), entry + max_len)], entry):
        out.append(i)
        if i.address > entry + 8:
            low = (i.mnemonic + " " + i.op_str).lower()
            if (i.mnemonic == "pop" and "pc" in i.op_str.lower()) or low.startswith("bx lr") or (
                i.mnemonic.startswith("ldm") and "pc" in i.op_str.lower()
            ):
                break
    return out


def nearest_prologue(c: Cs, data: bytes, target: int, window: int = 0x7000) -> int | None:
    best = None
    lo = max(0, target - window) & ~3
    for off in range(lo, min(target + 1, len(data) - 3), 4):
        one = list(c.disasm(data[off:off + 4], off, count=1))
        if not one:
            continue
        i = one[0]
        s = i.op_str.lower()
        if (i.mnemonic == "push" and "lr" in s) or (
            i.mnemonic.startswith("stm") and "sp!" in s and "lr" in s
        ):
            best = off
    return best


def direct_callers(data: bytes, target: int, cap: int = 100) -> list[int]:
    out = []
    for off in range(0, len(data) - 3, 4):
        if bl_target(off, u32(data, off)) == target:
            out.append(off)
            if len(out) >= cap:
                break
    return out


def direct_calls(data: bytes, insns) -> list[tuple[int, int]]:
    out = []
    for i in insns:
        if i.address + 4 > len(data):
            continue
        target = bl_target(i.address, u32(data, i.address))
        if target is not None:
            out.append((i.address, target))
    return out


def first_operand(op_str: str) -> str:
    return op_str.split(",", 1)[0].strip().lower() if op_str else ""


def defined_reg(i) -> str | None:
    if i.mnemonic.lower() not in DEF_MNEMONICS:
        return None
    reg = first_operand(i.op_str)
    return reg if reg in TRACKED_REGS else None


def regs_in_text(op_str: str) -> set[str]:
    return set(re.findall(r"\b(?:r(?:1[0-1]|[0-9])|sp|fp|lr)\b", op_str.lower()))


def mem_refs(i) -> list[tuple[str, int]]:
    """Extract simple [reg,#imm] / [reg] refs from printed ARM operands."""
    out = []
    for m in re.finditer(r"\[(r(?:1[0-1]|[0-9])|sp|fp),?\s*(?:#(-?0x[0-9a-f]+|-?\d+))?", i.op_str.lower()):
        base = m.group(1)
        raw = m.group(2)
        disp = int(raw, 0) if raw else 0
        out.append((base, disp))
    return out


def last_arg_defs(insns, stop_addr: int) -> dict[str, str]:
    last: dict[str, str] = {}
    for i in insns:
        if i.address >= stop_addr:
            break
        reg = defined_reg(i)
        if reg in ARG_REGS:
            last[reg] = fmt(i)
    return {r: last.get(r, "<no local definition found>") for r in ("r0", "r1", "r2", "r3")}


def context(insns, address: int, before: int = 28, after: int = 8):
    idx = next((n for n, i in enumerate(insns) if i.address == address), None)
    if idx is None:
        return []
    return insns[max(0, idx - before):min(len(insns), idx + after + 1)]


def provenance_map(insns):
    """Heuristic provenance labels for registers inside one function.

    Labels are intentionally textual, not symbolic-execution claims.  They make
    argument-derived structure offsets visible without silently solving aliases.
    """
    prov = {f"r{x}": f"entry_arg_r{x}" for x in range(4)}
    prov.update({f"r{x}": f"entry_r{x}" for x in range(4, 12)})
    rows = []
    for i in insns:
        mnem = i.mnemonic.lower()
        dst = defined_reg(i)
        if dst is not None:
            src_regs = [r for r in regs_in_text(i.op_str) if r != dst]
            label = None
            if mnem.startswith("mov") and src_regs:
                label = prov.get(src_regs[0], src_regs[0])
            elif mnem.startswith("ldr"):
                refs = mem_refs(i)
                if refs:
                    base, disp = refs[0]
                    label = f"mem({prov.get(base, base)}{disp:+#x})"
            elif mnem in {"add", "adds", "sub", "subs", "adr"} and src_regs:
                # Preserve base provenance and retain the textual arithmetic.
                label = f"addr({prov.get(src_regs[0], src_regs[0])}; {i.op_str})"
            if label is None:
                label = fmt(i)
            prov[dst] = label
        # Snapshot every call's argument provenance before the call clobbers r0-r3.
        rows.append((i.address, dict(prov)))
        if i.mnemonic.startswith("bl"):
            for r in ARG_REGS:
                prov[r] = f"call_result_or_clobber@0x{i.address:08X}"
    return {addr: p for addr, p in rows}


def memory_offset_inventory(insns, provenance_at: dict[int, dict[str, str]]):
    rows = []
    for i in insns:
        refs = mem_refs(i)
        if not refs:
            continue
        p = provenance_at.get(i.address, {})
        for base, disp in refs:
            label = p.get(base, base)
            if "entry_arg" in label or "mem(entry_arg" in label or "addr(entry_arg" in label:
                rows.append((i.address, i.mnemonic, base, disp, label, fmt(i)))
    return rows


def call_report(data: bytes, insns, address: int):
    defs = last_arg_defs(insns, address)
    prov_at = provenance_map(insns).get(address, {})
    target = bl_target(address, u32(data, address)) if address + 4 <= len(data) else None
    return target, defs, {r: prov_at.get(r, "?") for r in ("r0", "r1", "r2", "r3")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    c = md()

    anchor_ins = function(c, data, JOB)
    parent_ins = function(c, data, PARENT)
    orch_ins = function(c, data, ORCH)
    job_callers = direct_callers(data, JOB)

    caller_functions: dict[int, list[int]] = defaultdict(list)
    for callsite in job_callers:
        entry = nearest_prologue(c, data, callsite)
        if entry is not None:
            caller_functions[entry].append(callsite)

    lines = [
        "# M11-P still R2Y buffer/dataflow trace",
        "",
        f"- canonical unpacked SHA-256: `{digest}`",
        f"- still B2B/R2Y job: `0x{JOB:08X}`",
        f"- known parent: `0x{PARENT:08X}`",
        f"- higher orchestrator: `0x{ORCH:08X}`",
        f"- direct job callsites: `{[hex(x) for x in job_callers]}`",
        f"- distinct direct caller functions: `{[hex(x) for x in sorted(caller_functions)]}`",
        "",
        "## Interpretation policy",
        "",
        "This probe reports static argument provenance and structure-like offsets only. A register label is a locator, not proof of runtime aliasing. A direct Y/Cb/Cr-to-encoder closure requires a compiled consumer/dataflow chain, not string proximity or photographic matching.",
        "",
    ]

    # Direct callers: this is where the job input/output descriptors become visible.
    for entry, callsites in sorted(caller_functions.items()):
        ins = function(c, data, entry)
        prov = provenance_map(ins)
        lines += [f"## Direct caller function `0x{entry:08X}`", ""]
        for callsite in callsites:
            target, defs, args_prov = call_report(data, ins, callsite)
            lines += [
                f"### Call `0x{callsite:08X}` -> `0x{target:08X}`",
                "",
                "Last local r0-r3 definitions:",
            ]
            for r in ("r0", "r1", "r2", "r3"):
                lines.append(f"- `{r}`: `{defs[r]}`")
            lines += ["", "Heuristic provenance at call:"]
            for r in ("r0", "r1", "r2", "r3"):
                lines.append(f"- `{r}`: `{args_prov[r]}`")
            lines += ["", "Context:", "", "```asm"]
            lines += [fmt(i) for i in context(ins, callsite, 40, 10)]
            lines += ["```", ""]

        inv = memory_offset_inventory(ins, prov)
        if inv:
            lines += ["### Argument-derived memory references", "", "| address | op | base | disp | provenance | instruction |", "|---:|---|---|---:|---|---|"]
            for addr, mnem, base, disp, label, text in inv[:240]:
                lines.append(f"| `0x{addr:08X}` | `{mnem}` | `{base}` | `{disp:+#x}` | `{label}` | `{text}` |")
            lines.append("")

    # Inside the job, report every direct call and give extra context to known high-value callees.
    anchor_prov = provenance_map(anchor_ins)
    lines += ["## Still B2B/R2Y job calls", ""]
    for at, target in direct_calls(data, anchor_ins):
        _, defs, args_prov = call_report(data, anchor_ins, at)
        important = target in IMPORTANT_CALLEES
        lines += [f"### `0x{at:08X}` -> `0x{target:08X}`{'  **important**' if important else ''}", ""]
        for r in ("r0", "r1", "r2", "r3"):
            lines.append(f"- `{r}` last-def: `{defs[r]}`")
            lines.append(f"  provenance: `{args_prov[r]}`")
        if important:
            lines += ["", "```asm"]
            lines += [fmt(i) for i in context(anchor_ins, at, 34, 10)]
            lines += ["```"]
        lines.append("")

    inv = memory_offset_inventory(anchor_ins, anchor_prov)
    lines += ["### Job argument-derived memory references", ""]
    if inv:
        lines += ["| address | op | base | disp | provenance | instruction |", "|---:|---|---|---:|---|---|"]
        for addr, mnem, base, disp, label, text in inv[:320]:
            lines.append(f"| `0x{addr:08X}` | `{mnem}` | `{base}` | `{disp:+#x}` | `{label}` | `{text}` |")
    else:
        lines.append("No simple argument-derived memory references were recognized by this bounded heuristic.")
    lines.append("")

    # Known parent and higher orchestrator preserve post-call scheduling order.
    for name, entry, ins, focus_target in (
        ("known parent", PARENT, parent_ins, JOB),
        ("higher orchestrator", ORCH, orch_ins, PARENT),
    ):
        lines += [f"## {name.title()} `0x{entry:08X}` scheduling contexts", ""]
        calls = direct_calls(data, ins)
        focus = [(at, tgt) for at, tgt in calls if tgt == focus_target]
        if not focus:
            lines.append(f"No direct call to `0x{focus_target:08X}` found in recovered function boundary.")
        for at, tgt in focus:
            lines += [f"### Focus call `0x{at:08X}` -> `0x{tgt:08X}`", "", "```asm"]
            lines += [fmt(i) for i in context(ins, at, 44, 52)]
            lines += ["```", "", "Calls in the following local window:"]
            lo, hi = at, at + 0x220
            for a, t in calls:
                if lo < a <= hi:
                    lines.append(f"- `0x{a:08X}` -> `0x{t:08X}`")
            lines.append("")

    # Callee entry snippets: reveal whether they immediately dereference a buffer/control object.
    lines += ["## Important callee entry probes", ""]
    for target in sorted(IMPORTANT_CALLEES):
        ins = function(c, data, target, max_len=0x500)
        prov = provenance_map(ins)
        lines += [f"### `0x{target:08X}`", "", "```asm"]
        lines += [fmt(i) for i in ins[:100]]
        lines += ["```", ""]
        inv = memory_offset_inventory(ins, prov)
        if inv:
            lines += ["Argument-derived memory refs:"]
            for addr, mnem, base, disp, label, text in inv[:100]:
                lines.append(f"- `0x{addr:08X}` `{mnem}` `{base}{disp:+#x}` `{label}` — `{text}`")
            lines.append("")

    lines += [
        "## Closure rule",
        "",
        "A still-output closure may be promoted only if this trace (or a focused follow-up from one of its concrete callees/fields) shows the R2Y output descriptor carrying Y/Cb/Cr buffers into the downstream still/JPEG consumer without another image-processing conversion. If an intervening Y2R/RGB/gamut/transfer block appears, trace it first. No renderer change follows from this probe alone.",
        "",
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
