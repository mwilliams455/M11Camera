#!/usr/bin/env python3
"""Map every M11-P R2YS parameter family selected by saturation state.

Purpose
-------
The Category-42 creative maps exhibit an exact ``plateau+1`` Q9-like ladder,
but the +10 monochrome Cat42 map stores zero offsets/gains.  Before using the
monochrome map as evidence for direct ``code/512`` scale decoding, determine
whether saturation +10 also switches other R2Y categories that could perform
the final chroma kill.

This analyzer uses the already-recovered resolver semantics: descriptor flag
0x200 selects request field +0x2c, the saturation state.  It operates only on
the exact hash-gated M11-P 2.6.1 unpacked image and emits derived metadata.
It does not infer pixel arithmetic from parameter values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, map_bytes, parse_r2y

SAT_FLAG = 0x200
CREATIVE_STATES = {-3, -2, -1, 0, 1, 2, 3}
MONO_STATE = 10


def word_stats(raw: bytes) -> dict:
    out = {
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "nonzero_bytes": sum(b != 0 for b in raw),
        "all_zero_bytes": not any(raw),
    }
    if len(raw) % 2 == 0:
        u16 = struct.unpack("<" + "H" * (len(raw) // 2), raw)
        s16 = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        out.update({
            "u16_count": len(u16),
            "nonzero_u16": sum(v != 0 for v in u16),
            "u16_min": min(u16) if u16 else None,
            "u16_max": max(u16) if u16 else None,
            "s16_min": min(s16) if s16 else None,
            "s16_max": max(s16) if s16 else None,
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--markdown", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_UNPACKED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    base, _, _, descriptors = parse_r2y(data)
    sat_desc = [d for d in descriptors if d["flags"] & SAT_FLAG]
    if not sat_desc:
        raise AssertionError("no saturation-selected descriptors found")

    # The resolver consumes saturation from request +0x2c after all lower flag
    # fields. In the serialized dependency vector it is therefore the final
    # dependency whenever flag 0x200 is present.
    entries = []
    by_category: dict[int, list[dict]] = defaultdict(list)
    for d in sat_desc:
        if not d["dependencies_s32"]:
            raise AssertionError(f"category {d['category']} has SAT flag but no dependency")
        state = d["dependencies_s32"][-1]
        raw = map_bytes(data, base, d)
        e = {
            "index": d["index"],
            "category": d["category"],
            "flags": d["flags"],
            "flags_hex": d["flags_hex"],
            "descriptor_size": d["descriptor_size"],
            "map_size": d["map_size"],
            "map_offset_abs": d["map_offset_abs"],
            "dependencies": d["dependencies_s32"],
            "selector_prefix": d["dependencies_s32"][:-1],
            "saturation_state": state,
            "map": word_stats(raw),
        }
        entries.append(e)
        by_category[d["category"]].append(e)

    families = []
    complete_creative_categories = []
    mono_categories = []
    creative_plus_mono_categories = []
    for category, rows in sorted(by_category.items()):
        # A category may contain multiple ISO/other selector prefixes. Summarize
        # each prefix separately so +10 is not accidentally paired with a
        # different operating range.
        by_prefix: dict[tuple[int, ...], list[dict]] = defaultdict(list)
        for row in rows:
            by_prefix[tuple(row["selector_prefix"])].append(row)
        prefix_families = []
        cat_states = set()
        for prefix, prows in sorted(by_prefix.items()):
            prows.sort(key=lambda x: x["saturation_state"])
            states = [x["saturation_state"] for x in prows]
            cat_states.update(states)
            hashes = [x["map"]["sha256"] for x in prows]
            prefix_families.append({
                "selector_prefix": list(prefix),
                "states": states,
                "complete_creative": CREATIVE_STATES.issubset(states),
                "has_mono_10": MONO_STATE in states,
                "unique_map_hashes": len(set(hashes)),
                "map_sizes": sorted({x["map_size"] for x in prows}),
                "mono_map": next((x["map"] for x in prows if x["saturation_state"] == MONO_STATE), None),
            })
        if CREATIVE_STATES.issubset(cat_states):
            complete_creative_categories.append(category)
        if MONO_STATE in cat_states:
            mono_categories.append(category)
        if CREATIVE_STATES.issubset(cat_states) and MONO_STATE in cat_states:
            creative_plus_mono_categories.append(category)
        families.append({
            "category": category,
            "descriptor_count": len(rows),
            "states": sorted(cat_states),
            "flags": sorted({r["flags"] for r in rows}),
            "map_sizes": sorted({r["map_size"] for r in rows}),
            "prefix_families": prefix_families,
        })

    cat42 = next((f for f in families if f["category"] == 42), None)
    if cat42 is None:
        raise AssertionError("Category 42 missing from saturation fanout")
    if not ({*CREATIVE_STATES, MONO_STATE}.issubset(cat42["states"])):
        raise AssertionError(f"Category 42 state family changed: {cat42['states']}")

    # Find the exact Cat42 +10 row and report its parameter words explicitly.
    cat42_mono = next(e for e in entries if e["category"] == 42 and e["saturation_state"] == 10)
    cat42_mono_raw = map_bytes(data, base, next(d for d in descriptors if d["index"] == cat42_mono["index"]))
    cat42_mono_i16 = list(struct.unpack("<22h", cat42_mono_raw))

    report = {
        "schema": "m11camera.research.saturation_dependency_fanout.v1",
        "sha256": digest,
        "saturation_selector_flag": hex(SAT_FLAG),
        "saturation_selected_descriptor_count": len(sat_desc),
        "saturation_selected_categories": sorted(by_category),
        "complete_creative_categories": complete_creative_categories,
        "mono_state_10_categories": mono_categories,
        "creative_plus_mono_categories": creative_plus_mono_categories,
        "category42_mono_i16": cat42_mono_i16,
        "category42_mono_map_stats": cat42_mono["map"],
        "families": families,
        "entries": entries,
        "evidence_boundary": {
            "resolver_flag_0x200_to_saturation": "previously_closed_primary_firmware_semantics",
            "this_report_proves_pixel_scale_encoding": False,
            "purpose": "determine whether monochrome saturation +10 is Cat42-only or coordinated across additional R2Y categories",
        },
    }

    lines = [
        "# M11-P saturation dependency fanout", "",
        f"- SHA-256: `{digest}`",
        f"- descriptors with resolver saturation flag `0x200`: **{len(sat_desc)}**",
        f"- saturation-selected categories: `{sorted(by_category)}`",
        f"- categories containing all creative states -3..+3: `{complete_creative_categories}`",
        f"- categories containing monochrome state +10: `{mono_categories}`",
        f"- categories containing both creative family and +10: `{creative_plus_mono_categories}`",
        "", "## Families", "",
        "| category | descriptor count | states | map sizes | complete -3..+3 | has +10 |",
        "|---:|---:|---|---|:---:|:---:|",
    ]
    for f in families:
        complete = any(p["complete_creative"] for p in f["prefix_families"])
        mono = any(p["has_mono_10"] for p in f["prefix_families"])
        lines.append(
            f"| {f['category']} | {f['descriptor_count']} | {f['states']} | {f['map_sizes']} | {complete} | {mono} |"
        )
    lines += [
        "", "## Category 42 +10 map", "",
        f"- i16 words: `{cat42_mono_i16}`",
        f"- nonzero 16-bit words: `{cat42_mono['map'].get('nonzero_u16')}` / 22",
        "",
        "## Evidence boundary", "",
        "This report closes only the **selection fanout** of the saturation request. If +10 also selects other categories, monochrome cannot by itself decide Cat42 scale-code decoding. If Cat42 is the sole saturation-dependent family, its +10 zero map becomes materially stronger evidence for direct zero-preserving scale semantics, but the pixel equation still remains hardware-internal.",
        "",
    ]

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2) + "\n")
    args.markdown.write_text("\n".join(lines) + "\n")
    print(args.markdown)


if __name__ == "__main__":
    main()
