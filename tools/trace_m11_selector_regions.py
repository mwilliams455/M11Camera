#!/usr/bin/env python3
"""Map Leica M11-P R2Y selector strings to embedded executable/container regions.

Forensic-only helper. Input must be the exact decompressed M11-P 2.6.1 image.
The report contains derived metadata only: offsets, container/header metadata,
printable labels, hashes of bounded windows, and candidate address references.
It never emits proprietary firmware bytes.

Goal: bridge Leica's high-level img_macro_drv_r2y_* selector strings to the
low-level Milbeaut Im_R2Y_* driver layer before any renderer semantics change.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")

TARGETS = (
    b"RGBYB TABLE",
    b"img_macro_drv_r2y_select_gamma_paraset",
    b"E_IMG_MACRO_DRV_R2Y_CATEGORY_YC_R2Y6A",
    b"E_IMG_MACRO_DRV_R2Y_CATEGORY_YBlend_R2Y6A",
    b"Im_R2Y_Set_Gamma_Table",
    b"Im_R2Y_Ctrl_Gamma",
    b"Im_R2Y_Set_GammaYbTblAccessEnable",
    b"Im_R2Y_Set_GammaTblAccessEnable",
    b"Im_R2Y_Ctrl_Yc_Convert",
    b"Im_R2Y_Ctrl_YNR",
)

SIGS = {
    "ELF": b"\x7fELF",
    "ROMFS": b"-rom1fs-",
    "FDT/FIT": b"\xd0\x0d\xfe\xed",
    "uImage": b"\x27\x05\x19\x56",
    "gzip": b"\x1f\x8b\x08",
    "xz": b"\xfd7zXZ\x00",
    "squashfs-le": b"hsqs",
    "squashfs-be": b"sqsh",
}


def all_hits(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def safe_u32(data: bytes, off: int, endian: str) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, off)[0]


@dataclass(frozen=True)
class Container:
    kind: str
    start: int
    end: int
    load_addr: int | None = None
    entry_addr: int | None = None
    note: str = ""

    def contains(self, off: int) -> bool:
        return self.start <= off < self.end


def parse_uimages(data: bytes) -> list[Container]:
    out: list[Container] = []
    for off in all_hits(data, SIGS["uImage"]):
        if off + 64 > len(data):
            continue
        size = safe_u32(data, off + 12, ">")
        load = safe_u32(data, off + 16, ">")
        entry = safe_u32(data, off + 20, ">")
        if size is None or size == 0 or size > len(data):
            continue
        end = off + 64 + size
        if end > len(data):
            continue
        arch = data[off + 29]
        comp = data[off + 31]
        out.append(Container("uImage", off, end, load, entry, f"size={size} arch={arch} comp={comp}"))
    return out


def parse_fdts(data: bytes) -> list[Container]:
    out: list[Container] = []
    for off in all_hits(data, SIGS["FDT/FIT"]):
        total = safe_u32(data, off + 4, ">")
        if total is None or total < 40 or off + total > len(data):
            continue
        out.append(Container("FDT/FIT", off, off + total, note=f"totalsize={total}"))
    return out


def parse_elfs(data: bytes) -> list[Container]:
    out: list[Container] = []
    for off in all_hits(data, SIGS["ELF"]):
        if off + 0x34 > len(data):
            continue
        cls, enc = data[off + 4], data[off + 5]
        if cls not in (1, 2) or enc not in (1, 2):
            continue
        endian = "<" if enc == 1 else ">"
        try:
            if cls == 1:
                eh = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, off + 16)
                _etype, machine, _ver, entry, phoff, shoff, _flags, ehsize, phentsz, phnum, shentsz, shnum, _shstr = eh
                ph_fmt = endian + "IIIIIIII"
                ph_min = 32
            else:
                eh = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, off + 16)
                _etype, machine, _ver, entry, phoff, shoff, _flags, ehsize, phentsz, phnum, shentsz, shnum, _shstr = eh
                ph_fmt = endian + "IIQQQQQQ"
                ph_min = 56
        except struct.error:
            continue
        if ehsize < 0x34 or phnum > 4096 or shnum > 65535:
            continue
        extent = max(ehsize, phoff + phentsz * phnum, shoff + shentsz * shnum)
        load_candidates: list[int] = []
        if phnum and phentsz >= ph_min and off + phoff + phentsz * phnum <= len(data):
            for i in range(phnum):
                po = off + phoff + i * phentsz
                try:
                    vals = struct.unpack_from(ph_fmt, data, po)
                except struct.error:
                    break
                if cls == 1:
                    p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = vals
                else:
                    p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = vals
                if p_offset + p_filesz <= len(data) - off:
                    extent = max(extent, p_offset + p_filesz)
                if p_type == 1 and p_filesz:
                    load_candidates.append(p_vaddr - p_offset)
        if extent <= 0 or off + extent > len(data):
            continue
        load = load_candidates[0] if load_candidates and len(set(load_candidates)) == 1 else None
        out.append(Container(f"ELF{32 if cls == 1 else 64}", off, off + extent, load, entry,
                             f"machine={machine} endian={'LE' if enc == 1 else 'BE'} phnum={phnum} shnum={shnum}"))
    return out


def nearest_signature_hits(data: bytes, center: int, radius: int = 0x400000) -> list[tuple[int, str]]:
    lo, hi = max(0, center - radius), min(len(data), center + radius)
    rows: list[tuple[int, str]] = []
    for name, sig in SIGS.items():
        p = lo
        while True:
            p = data.find(sig, p, hi)
            if p < 0:
                break
            rows.append((p, name))
            p += 1
    rows.sort(key=lambda x: (abs(x[0] - center), x[0]))
    return rows[:24]


def nearest_fill_boundary(data: bytes, center: int, byte: int, direction: int, limit: int = 0x400000, min_run: int = 256) -> tuple[int, int] | None:
    """Find nearest run of >=min_run all-00 or all-ff without emitting bytes."""
    target = bytes([byte]) * min_run
    if direction < 0:
        lo = max(0, center - limit)
        p = data.rfind(target, lo, center)
    else:
        hi = min(len(data), center + limit)
        p = data.find(target, center, hi)
    if p < 0:
        return None
    start = p
    end = p + min_run
    while start > 0 and data[start - 1] == byte:
        start -= 1
    while end < len(data) and data[end] == byte:
        end += 1
    return start, end


def nearby_labels(data: bytes, center: int, radius: int = 0x500) -> list[tuple[int, str]]:
    lo, hi = max(0, center - radius), min(len(data), center + radius)
    rows = []
    for m in PRINTABLE_RE.finditer(data[lo:hi]):
        off = lo + m.start()
        text = m.group().decode("ascii", errors="replace")
        rows.append((off, text))
    rows.sort(key=lambda x: (abs(x[0] - center), x[0]))
    return rows[:40]


def runtime_addr(container: Container, file_off: int) -> int | None:
    if container.load_addr is None:
        return None
    # For uImage load address points to payload after its 64-byte header.
    payload_start = container.start + 64 if container.kind == "uImage" else container.start
    return container.load_addr + (file_off - payload_start)


def address_occurrences(data: bytes, value: int, lo: int, hi: int) -> list[int]:
    if value < 0 or value > 0xFFFFFFFF:
        return []
    needle = struct.pack("<I", value)
    out = []
    p = lo
    while True:
        p = data.find(needle, p, hi)
        if p < 0:
            return out
        out.append(p)
        p += 1


def disasm_metadata(data: bytes, off: int) -> list[str]:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    except Exception:
        return ["capstone unavailable"]
    lo = max(0, off - 24)
    hi = min(len(data), off + 28)
    code = data[lo:hi]
    out: list[str] = []
    for label, mode in (("ARM", CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), ("THUMB", CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)):
        md = Cs(CS_ARCH_ARM, mode)
        ins = list(md.disasm(code, lo))
        compact = "; ".join(f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in ins[:14])
        out.append(f"{label}: {compact}" if compact else f"{label}: no decode")
    return out


def report(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"unexpected unpacked SHA-256 {digest}")

    containers = parse_uimages(data) + parse_fdts(data) + parse_elfs(data)
    containers.sort(key=lambda c: (c.start, c.end))

    lines = [
        "# M11-P R2A selector / executable-region trace",
        "",
        "Evidence state: **derived directly from exact M11-P 2.6.1 unpacked firmware**.",
        "",
        f"- unpacked size: `{len(data)}`",
        f"- unpacked SHA-256: `{digest}`",
        f"- validated embedded ELF/uImage/FDT containers: `{len(containers)}`",
        "",
        "## Validated containers",
        "",
    ]
    for c in containers:
        lines.append(f"- `{c.kind}` `0x{c.start:08x}..0x{c.end:08x}` load={c.load_addr if c.load_addr is not None else 'unknown'} entry={c.entry_addr if c.entry_addr is not None else 'unknown'} — {c.note}")
    if not containers:
        lines.append("- none")

    lines += ["", "## Target mapping", ""]
    for needle in TARGETS:
        hits = all_hits(data, needle)
        label = needle.decode("ascii", errors="replace")
        lines.append(f"### `{label}` — {len(hits)} hit(s)")
        lines.append("")
        for off in hits[:32]:
            lines.append(f"- absolute offset: `0x{off:08x}`")
            win = data[max(0, off-0x1000):min(len(data), off+0x1000)]
            lines.append(f"- ±0x1000 window SHA-256: `{hashlib.sha256(win).hexdigest()}`")
            owners = [c for c in containers if c.contains(off)]
            if owners:
                for c in owners:
                    ra = runtime_addr(c, off)
                    lines.append(f"- container: `{c.kind}` `0x{c.start:08x}..0x{c.end:08x}`; runtime-address estimate: `{f'0x{ra:08x}' if ra is not None else 'unknown'}`")
                    if ra is not None:
                        refs = address_occurrences(data, ra, c.start, c.end)
                        lines.append(f"  - little-endian 32-bit occurrences of runtime address inside container: `{len(refs)}`")
                        for roff in refs[:16]:
                            lines.append(f"    - candidate literal/reference at `0x{roff:08x}`")
                            for text in disasm_metadata(data, roff):
                                lines.append(f"      - {text}")
            else:
                lines.append("- container: no validated ELF/uImage/FDT extent owns this offset")

            # Even without a load mapping, record direct offset literals as a conservative probe.
            refs = address_occurrences(data, off, max(0, off-0x800000), min(len(data), off+0x800000))
            lines.append(f"- direct little-endian file-offset occurrences within ±8 MiB: `{len(refs)}`")
            for roff in refs[:12]:
                if roff == off:
                    continue
                lines.append(f"  - candidate at `0x{roff:08x}`")
                for text in disasm_metadata(data, roff):
                    lines.append(f"    - {text}")

            for b, name in nearest_signature_hits(data, off):
                lines.append(f"- nearby signature `{name}` at `0x{b:08x}` (delta `{b-off:+#x}`)")
            for byte, tag in ((0x00, "00"), (0xFF, "FF")):
                for direction, dname in ((-1, "before"), (1, "after")):
                    r = nearest_fill_boundary(data, off, byte, direction)
                    if r:
                        lines.append(f"- nearest >=256-byte `{tag}` fill {dname}: `0x{r[0]:08x}..0x{r[1]:08x}`")
            lines.append("- nearby printable labels:")
            for poff, text in nearby_labels(data, off):
                safe = text.replace("`", "'")
                lines.append(f"  - `{poff-off:+#x}` / `0x{poff:08x}` — `{safe}`")
            lines.append("")
        if len(hits) > 32:
            lines.append(f"First 32 shown; {len(hits)-32} omitted.")
            lines.append("")

    lines += [
        "## Interpretation boundary",
        "",
        "This probe maps container/signature context and candidate address literals only. A literal/reference candidate is not a proven code xref. Gamma table index, GMMD/GAMSW runtime values, and category-to-consumer assignments remain OPEN until an instruction-level callsite or an exact parameter-structure mapping closes them.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("unpacked", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    data = args.unpacked.read_bytes()
    text = report(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text + "\n")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
