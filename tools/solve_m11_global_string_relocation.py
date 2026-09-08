#!/usr/bin/env python3
"""Solve M11-P R2Y string relocation across the *whole* exact firmware image.

Earlier relocation probes intentionally searched pointer words only inside the
same zero-fill-bounded string-rich region.  That is insufficient if the region
is .rodata and ARM text/literal pools live elsewhere.  This probe searches all
4-byte-aligned words in the exact unpacked image.

For each R2Y group, runtime pointers must preserve the exact pairwise spacing of
multiple independent firmware strings.  Starting from one anchor, candidate
pointer values are progressively intersected against the remaining target
offsets.  Any surviving relocation delta is then mapped back to literal slots
and nearby A32 PC-relative LDR instructions.

Output is derived addresses/counts/disassembly metadata only; firmware bytes are
never emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

import numpy as np

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
MASK32 = 0xFFFFFFFF

GROUPS = {
    "leica_selector": [
        b"(r2y) R2Y GAMMA already loaded",
        b"NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset",
        b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2",
        b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3",
        b"-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1",
        b"(r2y) R2Y YC already loaded",
        b"NO VALID STRING:  E_IMG_MACRO_DRV_R2Y_CATEGORY_YC_R2Y6A  img_macro_drv_r2y_select_yc_paraset YC",
        b"NO VALID STRING: E_IMG_MACRO_DRV_R2Y_CATEGORY_YBlend_R2Y6A  img_macro_drv_r2y_select_yc_paraset  BLEND",
        b"(r2y) R2Y ToneTable already loaded",
        b"NO VALID STRING   img_macro_drv_r2y_select_colorcorrection1_paraset",
    ],
    "milbeaut_driver": [
        b"Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL",
        b"Im_R2Y_Ctrl_Gamma error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Set_GammaTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Set_GammaYbTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Ctrl_CC1_Matrix error. r2y_ctrl_cc = NULL",
        b"Im_R2Y_Ctrl_Yc_Convert error. r2y_ctrl_ycc = NULL",
        b"Im_R2Y_Ctrl_Ynr error. r2y_ctrl_ynr = NULL",
        b"Im_R2Y_Ctrl_Color_NR error. r2y_ctrl_clpf = NULL",
        b"Im_R2Y_Ctrl_Chroma_Suppress error. r2y_ctrl_cs = NULL",
        b"Im_R2Y_Set_Gamma_Table error. tbl_index > 4",
    ],
}


def unique_hit(data: bytes, needle: bytes) -> int:
    p = data.find(needle)
    if p < 0 or data.find(needle, p + 1) >= 0:
        raise ValueError(f"target is not unique: {needle!r}")
    return p


def contains_sorted(sorted_u32: np.ndarray, values_u32: np.ndarray) -> np.ndarray:
    idx = np.searchsorted(sorted_u32, values_u32)
    ok = idx < sorted_u32.size
    out = np.zeros(values_u32.shape, dtype=bool)
    if np.any(ok):
        oi = idx[ok]
        out[ok] = sorted_u32[oi] == values_u32[ok]
    return out


def a32_literal_xrefs(data: bytes, slot: int) -> list[int]:
    """Find strict A32 LDR Rt,[PC,+/-imm12] whose effective address is slot."""
    out: list[int] = []
    lo = max(0, slot - 0x1010)
    hi = min(len(data) - 4, slot + 0x1010)
    p = (lo + 3) & ~3
    while p <= hi:
        w = struct.unpack_from("<I", data, p)[0]
        # cond != NV; single data transfer immediate; P=1; W=0; L=1; Rn=PC.
        cond = (w >> 28) & 0xF
        if (
            cond != 0xF
            and ((w >> 26) & 0x3) == 0x1
            and ((w >> 25) & 1) == 0
            and ((w >> 24) & 1) == 1
            and ((w >> 21) & 1) == 0
            and ((w >> 20) & 1) == 1
            and ((w >> 16) & 0xF) == 0xF
        ):
            imm = w & 0xFFF
            addr = p + 8 + imm if ((w >> 23) & 1) else p + 8 - imm
            if addr == slot:
                out.append(p)
        p += 4
    return out


def disasm(data: bytes, off: int, count: int = 18) -> str:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except Exception:
        return "capstone unavailable"
    lo = max(0, off - 24) & ~3
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(data[lo : min(len(data), off + 72)], lo))
    return "; ".join(f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in ins[:count])


def solve_group(data: bytes, all_words: np.ndarray, unique_words: np.ndarray, name: str, needles: list[bytes]) -> list[str]:
    targets = [unique_hit(data, n) for n in needles]
    anchor = targets[0]

    # A runtime pointer to target_i equals anchor_pointer + (target_i-anchor)
    # modulo 2^32.  Begin with every distinct aligned 32-bit word globally and
    # progressively require the translated value for each independent target.
    cand = unique_words.copy()
    support_progress: list[tuple[int, int]] = []
    for t in targets[1:]:
        diff = np.uint64((t - anchor) & MASK32)
        expected = ((cand.astype(np.uint64) + diff) & MASK32).astype(np.uint32)
        keep = contains_sorted(unique_words, expected)
        cand = cand[keep]
        support_progress.append((t, int(cand.size)))
        if cand.size == 0:
            break

    lines = [
        f"### {name}",
        "",
        f"- unique target strings: `{len(targets)}`",
        f"- target span: `0x{min(targets):08x}..0x{max(targets):08x}`",
        "- candidate count after each additional independent spacing constraint:",
    ]
    for t, count in support_progress:
        lines.append(f"  - through target `0x{t:08x}`: `{count}`")
    lines.append(f"- final common pointer candidates: `{int(cand.size)}`")

    # Keep report bounded even if the hypothesis is poor.
    for pointer0 in cand[:32]:
        p0 = int(pointer0)
        delta = (p0 - anchor) & MASK32
        lines.append(f"- candidate anchor pointer `0x{p0:08x}` => relocation delta `0x{delta:08x}`")
        coherent = 0
        for t, needle in zip(targets, needles):
            ptr = (t + delta) & MASK32
            # Locate literal slots globally only after the candidate set is tiny.
            slots_idx = np.flatnonzero(all_words == np.uint32(ptr))
            slots = [int(i) * 4 for i in slots_idx[:16]]
            if slots:
                coherent += 1
            label = needle.decode("ascii", errors="replace")
            lines.append(f"  - `{label}` file `0x{t:08x}` runtime `0x{ptr:08x}` slots `{len(slots_idx)}`")
            for slot in slots[:6]:
                refs = a32_literal_xrefs(data, slot)
                lines.append(f"    - literal slot `0x{slot:08x}` A32 LDR xrefs `{len(refs)}`")
                for ref in refs[:4]:
                    lines.append(f"      - xref `0x{ref:08x}` — `{disasm(data, ref)}`")
        lines.append(f"  - targets with at least one literal slot: `{coherent}/{len(targets)}`")
    lines.append("")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    data = args.unpacked.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    aligned_len = len(data) & ~3
    all_words = np.frombuffer(memoryview(data)[:aligned_len], dtype="<u4")
    unique_words = np.unique(all_words)

    lines = [
        "# M11-P whole-firmware R2Y string relocation solve",
        "",
        f"- exact unpacked SHA-256: `{digest}`",
        f"- globally aligned uint32 words: `{all_words.size}`",
        f"- globally unique uint32 values: `{unique_words.size}`",
        "",
        "## Results",
        "",
    ]
    for name, needles in GROUPS.items():
        lines += solve_group(data, all_words, unique_words, name, needles)

    lines += [
        "## Interpretation boundary",
        "",
        "A surviving delta is strong relocation evidence only if it preserves all independent target spacings and the resulting pointer values occur in plausible literal slots. A32 LDR-to-slot matches add code-xref evidence, but function identity still requires coherent control flow. No renderer behavior is changed by this probe.",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
