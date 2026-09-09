#!/usr/bin/env python3
"""Improved BB06 opcode inventory for exact M11-P firmware.

Version 1 intentionally recognized only MOVW+MOVT constant construction and
therefore undercounted the common GCC pattern `mov rN,#low ; movt rN,#0xbb06`.
This pass recognizes both forms, associates the nearest proven BB06 opcode with
each direct call to 0x015765b4, and emits the complete submit routine through
the next A32 prologue candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

import trace_m11_bb06_packet_submit as v1

EXPECTED_SHA256 = v1.EXPECTED_SHA256
SUBMIT = v1.SUBMIT
SCAN_START = v1.SCAN_START
SCAN_END = v1.SCAN_END


def decode_mov_low(md: Cs, data: bytes, off: int, rd: int) -> tuple[int, str] | None:
    d = v1.mov_imm16(v1.u32(data, off))
    if d is not None and d[0] == "movw" and d[1] == rd:
        return d[2], "movw"
    ins = next(md.disasm(data[off:off+4], off), None)
    if ins is None or not ins.mnemonic.startswith("mov"):
        return None
    regname = f"r{rd}" if rd < 13 else {13:"sp",14:"lr",15:"pc"}[rd]
    m = re.fullmatch(rf"{re.escape(regname)}, #(0x[0-9a-f]+|[0-9]+)", ins.op_str)
    if not m:
        return None
    value = int(m.group(1), 0)
    if 0 <= value <= 0xFFFF:
        return value, ins.mnemonic
    return None


def find_bb06_constructs(data: bytes, start: int, end: int) -> list[dict]:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    out = []
    end = min(end, len(data) - 4)
    for movt_off in range(max(0, start) & ~3, end & ~3, 4):
        d = v1.mov_imm16(v1.u32(data, movt_off))
        if d is None or d[0] != "movt" or d[2] != 0xBB06:
            continue
        rd = d[1]
        low = None
        low_off = None
        source = None
        for p in range(movt_off - 4, max(start - 4, movt_off - 0x30), -4):
            row = decode_mov_low(md, data, p, rd)
            if row is not None:
                low, source = row
                low_off = p
                break
            # Stop if another MOVW/MOVT writes the same register before a low
            # setter is found; crossing it would make the reconstruction unsafe.
            x = v1.mov_imm16(v1.u32(data, p))
            if x is not None and x[1] == rd:
                break
        if low is None:
            out.append({"low_off":None,"movt":movt_off,"reg":rd,"low":None,"value":None,"source":None})
        else:
            out.append({
                "low_off":low_off,
                "movt":movt_off,
                "reg":rd,
                "low":low,
                "value":0xBB060000 | low,
                "source":source,
            })
    return out


def next_prologue(data: bytes, start: int, limit: int = 0x1000) -> int:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    for off in range(start + 4, min(len(data)-4, start+limit), 4):
        ins = next(md.disasm(data[off:off+4], off), None)
        if ins is None:
            continue
        if ins.mnemonic in ("push","stmdb") and "lr" in ins.op_str and (ins.mnemonic == "push" or "sp" in ins.op_str):
            return off
    return min(len(data), start + limit)


def nearby_strings(data: bytes, call: int, radius: int = 0x240) -> list[str]:
    rows=[]
    start=max(SCAN_START, call-radius)
    end=min(len(data)-4, call+0x40)
    for off in range(start & ~3, end & ~3, 4):
        lit=v1.literal_value(data,off,v1.u32(data,off))
        if lit is None:
            continue
        _,value,_=lit
        ann=v1.data_annotation(data,value)
        if ann:
            rows.append(ann)
    # keep the most selector-like unique strings first
    uniq=[]
    for s in rows:
        if s not in uniq:
            uniq.append(s)
    uniq.sort(key=lambda s:("select_" not in s and "paraset" not in s, s))
    return uniq[:8]


def report(data: bytes) -> str:
    digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P unpacked SHA-256 {digest}")

    calls=v1.find_submit_calls(data)
    constructs=find_bb06_constructs(data,SCAN_START,min(SCAN_END,len(data)))
    proven=[r for r in constructs if r["value"] is not None]
    by_low=Counter(r["low"] for r in proven)

    lines=[
        "# M11-P R2A BB06 packet opcode inventory v2",
        "",
        f"- SHA-256: `{digest}`",
        f"- common submit: `0x{SUBMIT:08x}`",
        f"- direct submit calls: `{len(calls)}`",
        f"- proven BB06 constructions: `{len(proven)}`; unresolved MOVT-high-only sites: `{len(constructs)-len(proven)}`",
        "- low words are packet/opcode identifiers only; no R2YS Category equivalence is assumed.",
        "",
        "## Global BB06 opcode frequency",
        "",
    ]
    for low,n in sorted(by_low.items(),key=lambda kv:(kv[0])):
        lines.append(f"- `0x{low:04x}` / `0xBB06{low:04X}`: `{n}`")

    lines += ["", "## Direct submit call associations", ""]
    for call in calls:
        pro=v1.nearest_prologue(data,call) or max(SCAN_START,call-0x400)
        candidates=[r for r in proven if pro <= r["movt"] <= call]
        candidates.sort(key=lambda r:call-r["movt"])
        nearest=candidates[0] if candidates else None
        lines += [f"### call `0x{call:08x}` (nearest prologue `0x{pro:08x}`)", ""]
        if nearest:
            lines.append(
                f"- nearest preceding BB06: `0x{nearest['value']:08x}` "
                f"from `{nearest['source']}` at `0x{nearest['low_off']:08x}` + MOVT `0x{nearest['movt']:08x}` "
                f"(distance `0x{call-nearest['movt']:x}`)"
            )
        else:
            lines.append("- nearest preceding BB06 in function window: none")
        strings=nearby_strings(data,call)
        if strings:
            lines.append("- nearby exact data-affine printable literal(s):")
            for s in strings:
                lines.append(f"  - {s}")
        lines.append("")

    lines += ["## BB06 constructions with nearest selector context", ""]
    for r in proven:
        strings=nearby_strings(data,r["movt"],0x180)
        context = strings[0] if strings else "no printable selector literal nearby"
        lines.append(
            f"- `0x{r['value']:08x}`: low at `0x{r['low_off']:08x}` ({r['source']}), "
            f"MOVT at `0x{r['movt']:08x}` — {context}"
        )

    end=next_prologue(data,SUBMIT,0x800)
    lines += [
        "",
        "## Complete common-submit body through next prologue",
        "",
        f"- next prologue candidate: `0x{end:08x}`",
        "```text",
    ]
    lines.extend(v1.window_disasm(data,SUBMIT,end))
    lines += [
        "```",
        "",
        "## Interpretation boundary",
        "",
        "Opcode association requires a reconstructed low immediate and MOVT 0xBB06 in the same bounded caller context. A shared opcode namespace does not imply direct equality with R2YS descriptor category numbers.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("unpacked",type=Path)
    ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(report(a.unpacked.read_bytes()))
    print(a.output)


if __name__ == "__main__":
    main()
