#!/usr/bin/env python3
"""Calibrate Leica M11-P indirect code-pointer affine base from gamma serializer tables.

The gamma selector and the 0x1400 serializer independently switch on the same
object subtype accessor (1..6). Their A32 `ldr pc,[pc,index,lsl#2]` tables store
absolute code-space words that require an affine translation to raw firmware
offsets. Earlier gamma-only solving was ambiguous. This pass jointly scores one
constant base across two serializer tables and two gamma-selector tables.

Primary evidence only: exact hash-gated Leica firmware. No public Milbeaut code
is used here.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
TABLES = [
    ("gamma_subtype6", 0x01579444, 6, 0x0157933C, 0x01579BF8),
    ("gamma_pair4",    0x015799FC, 4, 0x0157933C, 0x01579BF8),
    ("serializer_type0_subtype6", 0x015A6544, 6, 0x015A6374, 0x015A6700),
    ("serializer_type1_subtype6", 0x015A6570, 6, 0x015A6374, 0x015A6700),
]
SERIALIZER_CAL = [t for t in TABLES if t[0].startswith("serializer_")]
KNOWN_SERIALIZER_CALLEES = {
    0x015A4504, 0x015A4464, 0x015A43F0, 0x015A4284, 0x015A4138, 0x015A4024,
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


def entries(data: bytes, table: int, count: int) -> list[int]:
    return [u32(data, table + i*4) for i in range(count)]


def valid_a32_start(data: bytes, off: int, span: int = 6) -> tuple[bool,int,list[str]]:
    if off < 0 or off + 4 > len(data) or off & 3:
        return False,0,[]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[off:min(len(data),off+span*4)], off))
    if not insns or insns[0].address != off:
        return False,0,[]
    score = min(len(insns), span)
    text = [f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in insns]
    return True,score,text


def nearby_known_builder_call(data: bytes, off: int, words: int = 12) -> bool:
    for p in range(off, min(len(data)-4, off+words*4), 4):
        bt = bl_target(p, u32(data,p))
        if bt in KNOWN_SERIALIZER_CALLEES:
            return True
    return False


def candidate_bases(data: bytes) -> list[dict]:
    # Generate base candidates from serializer table words mapping to any
    # 4-byte-aligned raw address within the serializer body. Then require all
    # serializer entries and all gamma entries to map into their own bounded
    # function ranges under that same base.
    seeds = set()
    for _,table,count,start,end in SERIALIZER_CAL:
        for w in entries(data,table,count):
            for target in range(start & ~3, end & ~3, 4):
                seeds.add((w - target) & 0xFFFFFFFF)

    rows=[]
    for base in seeds:
        all_inside=True
        valid_score=0
        builder_score=0
        table_maps=[]
        for name,table,count,start,end in TABLES:
            vals=entries(data,table,count)
            mapped=[(w-base)&0xFFFFFFFF for w in vals]
            inside=sum(1 for x in mapped if start <= x < end and not (x&3))
            if inside != count:
                all_inside=False
                break
            v=0;b=0
            for x in mapped:
                ok,s,_=valid_a32_start(data,x)
                if ok:
                    v+=1; valid_score+=s
                if name.startswith("serializer_") and nearby_known_builder_call(data,x):
                    b+=1; builder_score+=1
            table_maps.append((name,mapped,v,b))
        if not all_inside:
            continue
        unique_targets=sum(len(set(m)) for _,m,_,_ in table_maps)
        rows.append({
            "base":base,
            "valid_score":valid_score,
            "builder_score":builder_score,
            "unique_targets":unique_targets,
            "maps":table_maps,
        })
    rows.sort(key=lambda r:(-r["builder_score"],-r["valid_score"],-r["unique_targets"],r["base"]))
    return rows


def report(data: bytes) -> str:
    digest=hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected M11-P SHA-256 {digest}")
    rows=candidate_bases(data)
    lines=[
        "# M11-P R2A gamma/serializer code-pointer affine calibration", "",
        f"- SHA-256: `{digest}`",
        "- requirement: one affine base must map every entry of all four tables into its independently bounded Leica function body.",
        f"- surviving joint bases: `{len(rows)}`", "",
        "## Raw table words", "",
    ]
    for name,table,count,start,end in TABLES:
        vals=entries(data,table,count)
        lines.append(f"- `{name}` table `0x{table:08x}`: "+", ".join(f"`0x{x:08x}`" for x in vals))
    lines += ["", "## Best joint-base candidates", ""]
    for row in rows[:40]:
        lines.append(
            f"### base `0x{row['base']:08x}` — serializer-builder score `{row['builder_score']}`, A32 validity score `{row['valid_score']}`, summed unique targets `{row['unique_targets']}`"
        )
        for name,mapped,v,b in row["maps"]:
            lines.append(f"- `{name}`: valid-starts `{v}/{len(mapped)}`, builder-near `{b}`; mapped " + ", ".join(f"`0x{x:08x}`" for x in mapped))
        lines.append("")
    if rows:
        best=rows[0]
        lines += ["## Best-candidate target snippets", ""]
        for name,mapped,_,_ in best["maps"]:
            lines.append(f"### `{name}`")
            for i,x in enumerate(mapped):
                ok,_,txt=valid_a32_start(data,x,8)
                lines.append(f"- index `{i}` -> `0x{x:08x}`: `{' ; '.join(txt[:8]) if ok else 'invalid'}`")
            lines.append("")
    lines += [
        "## Interpretation boundary", "",
        "A unique or strongly dominant joint base would resolve the indirect table raw targets, but it does not assign photographic meanings to subtype numbers. Those meanings still require payload/caller evidence.", ""
    ]
    return "\n".join(lines)


def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument("unpacked",type=Path); ap.add_argument("--output",type=Path,required=True); a=ap.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(report(a.unpacked.read_bytes())); print(a.output)


if __name__ == "__main__":
    main()
