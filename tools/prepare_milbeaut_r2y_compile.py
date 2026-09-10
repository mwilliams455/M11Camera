#!/usr/bin/env python3
"""Prepare the pinned public Milbeaut R2Y sources for compiler fingerprinting.

This helper is deliberately compile-only.  It repairs mechanical ETK/header
refactor drift around the exact pinned public source without changing R2Y
processing logic.  All R2Y tag/member spellings are derived from the pinned
generated headers by unique normalized-name correspondence.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
from pathlib import Path

KOBJECT_SHIM = r'''#ifndef R2A_COMPILE_ONLY_KOBJECT_H
#define R2A_COMPILE_ONLY_KOBJECT_H
#include <stddef.h>
typedef signed char kint8;
typedef unsigned char kuint8;
typedef signed short kint16;
typedef unsigned short kuint16;
typedef signed int kint32;
typedef unsigned int kuint32;
typedef signed long long kint64;
typedef unsigned long long kuint64;
typedef signed long klong;
typedef unsigned long kulong;
typedef unsigned char kuchar;
typedef void VOID;
typedef char CHAR;
typedef unsigned char UCHAR;
typedef signed char INT8;
typedef unsigned char UINT8;
typedef signed short SHORT;
typedef unsigned short USHORT;
typedef signed short INT16;
typedef unsigned short UINT16;
typedef signed int INT32;
typedef unsigned int UINT32;
typedef signed long LONG;
typedef unsigned long ULONG;
typedef signed long long LLONG;
typedef unsigned long long ULLONG;
typedef int BOOL;
typedef float FLOAT;
typedef double DOUBLE;
typedef unsigned long KConstType;
typedef struct _KObject { void *opaque; } KObject;
#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define K_TYPE_CHECK_INSTANCE_CAST(obj, TypeName) ((TypeName *)(obj))
#define K_TYPE_CHECK_INSTANCE_TYPE(obj, type_id) (1)
#define K_OBJECT_GET_PRIVATE(obj, PrivateType, type_id) ((PrivateType *)0)
#define K_TYPE_DEFINE_WITH_PRIVATE(TypeName, type_name)
extern void *k_object_new_with_private(KConstType type_id, unsigned long private_size);
#endif
'''


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def ensure_symlink(link: Path, target: Path) -> None:
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)
    if not link.exists():
        raise RuntimeError(f"failed symlink: {link} -> {target}")


def patch_external_compat(root: Path) -> None:
    workspace = root.parent.parent

    shim = workspace / "fj/klib/src/kobject.h"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text(KOBJECT_SHIM)

    inc = root / "include"
    shutil.copyfile(
        root / "Project/DeviceDriver/ARM/src/ddimtypedef.h",
        inc / "ddim_typedef.h",
    )
    custom_src = root / "Project/PalladiumTest/src/ddimusercustom.h"
    custom_dst = inc / "ddimusercustom.h"
    text = custom_src.read_text(errors="ignore")
    text = text.replace("(DdimUserCustom *self,VOID)", "(DdimUserCustom *self)")
    text = re.sub(
        r"^#endif\s*//\s*_DDIM_USER_CUSTOM_H_\s*$",
        "",
        text,
        flags=re.MULTILINE,
    )
    custom_dst.write_text(text)
    ensure_symlink(inc / "ddim_user_custom.h", Path("ddimusercustom.h"))

    arm_src = root / "Project/DeviceDriver/ARM/src"
    lsitop_src = root / "Project/DeviceDriver/LSITop/src"
    for name in ("ddtop.h", "ddtopone.h", "ddtoptwo.h", "ddtopthree.h", "ddtopfour.h"):
        src = lsitop_src / name
        if not src.is_file():
            raise RuntimeError(f"missing pinned TOP header: {src}")
        ensure_symlink(arm_src / name, Path("../../LSITop/src") / name)
    ensure_symlink(arm_src / "dd_arm.h", Path("ddarm.h"))

    target_src = root / "Project/ImageMacro/src"
    for path in (target_src / "imr2yset.c", target_src / "imr2yctrl2.c"):
        target_text = path.read_text(errors="ignore")
        if re.search(r"DD_ARM_WAIT_NS|DdTopone_UCLK40I", target_text):
            raise RuntimeError(f"unsafe to remove ddtop.h: target uses TOP timing macro: {path}")
    ddarm = arm_src / "ddarm.h"
    ddarm_text = ddarm.read_text(errors="ignore")
    if '#include "ddtop.h"' not in ddarm_text:
        raise RuntimeError("expected pre-refactor ddtop.h include not found in ddarm.h")
    ddarm.write_text(ddarm_text.replace('#include "ddtop.h"\n', ""))

    chiptop_src = root / "MILB_Header/Project/Top/src"
    for name in ("kchiptop1.h", "kchiptop2.h", "kchiptop3.h"):
        src = chiptop_src / name
        if not src.is_file():
            raise RuntimeError(f"missing pinned KChiptop header: {src}")
        ensure_symlink(arm_src / name, src)

    reginc = root / "MILB_Header/include/Image"
    ensure_symlink(reginc / "__fr2y6a.h", Path("fr2y6a.h"))
    ensure_symlink(reginc / "__jdsr2y_f2e_sram.h", Path("jdsr2yf2esram.h"))


def generated_tag_maps(root: Path) -> dict[str, dict[str, str]]:
    generated = ""
    for path in (root / "MILB_Header").rglob("*.h"):
        generated += "\n" + path.read_text(errors="ignore")

    maps: dict[str, dict[str, str]] = {}
    for kind in ("union", "struct"):
        pat = (
            r"typedef\s+"
            + kind
            + r"\s+(_IoR2y[A-Za-z0-9_]*)\s+IoR2y[A-Za-z0-9_]*\s*;"
        )
        tags = sorted(set(re.findall(pat, generated)))
        by_norm: dict[str, str] = {}
        collisions: dict[str, set[str]] = {}
        for tag in tags:
            key = norm(tag[len("_IoR2y") :])
            if key in by_norm and by_norm[key] != tag:
                collisions.setdefault(key, {by_norm[key]}).add(tag)
            else:
                by_norm[key] = tag
        if collisions:
            raise RuntimeError(f"ambiguous generated {kind} tags: {collisions}")
        maps[kind] = by_norm
    return maps


def bridge_tags(root: Path, targets: list[Path]) -> None:
    maps = generated_tag_maps(root)
    replacements: list[tuple[str, str, str, str]] = []
    unresolved: list[tuple[str, str, str]] = []

    for path in targets:
        text = path.read_text()
        for kind in ("union", "struct"):
            old_tags = sorted(
                set(re.findall(r"\b" + kind + r"\s+(io_r2y(?:_[A-Za-z0-9_]+)?)", text))
            )
            for old in old_tags:
                suffix = old[len("io_r2y") :].lstrip("_")
                new = maps[kind].get(norm(suffix))
                if not new:
                    unresolved.append((path.name, kind, old))
                    continue
                text = re.sub(
                    r"\b" + kind + r"\s+" + re.escape(old) + r"\b",
                    kind + " " + new,
                    text,
                )
                replacements.append((path.name, kind, old, new))
        path.write_text(text)

    if unresolved:
        raise RuntimeError(
            "unresolved old R2Y tags: "
            + ", ".join(f"{p}:{k} {t}" for p, k, t in unresolved)
        )

    required = {
        ("union", "io_r2y_ee0ctl", "_IoR2yEe0ctl"),
        ("struct", "io_r2y_mck", "_IoR2yMck"),
        ("struct", "io_r2y_mcl", "_IoR2yMcl"),
        ("struct", "io_r2y", "_IoR2y"),
        ("struct", "io_r2y_sram", "_IoR2ySram"),
    }
    seen = {(kind, old, new) for _, kind, old, new in replacements}
    if not required.issubset(seen):
        raise RuntimeError("expected EE0CTL/MCK/MCL/base/SRAM refactor bridge missing")

    print(f"bridged {len(replacements)} exact R2Y union/struct tag use(s)")


def generated_members(root: Path) -> set[str]:
    # fr2y6a.h contains the register/bitfield members; jdsr2yf2esram.h the
    # SRAM table members; Project/Image/src/jdsr2yf2e.h the top-level IoR2y
    # aggregate (`fR2y`).  This third source is essential and is the exact
    # generated evidence for the historical `F_R2Y` spelling.
    paths = [
        root / "MILB_Header/include/Image/fr2y6a.h",
        root / "MILB_Header/include/Image/jdsr2yf2esram.h",
        root / "MILB_Header/Project/Image/src/jdsr2yf2e.h",
    ]
    members: set[str] = set()
    for path in paths:
        if not path.is_file():
            raise RuntimeError(f"missing pinned generated R2Y header: {path}")
        for raw in path.read_text(errors="ignore").splitlines():
            line = re.sub(r"/\*.*?\*/", "", raw)
            bit = re.search(r"\b([a-z][A-Za-z0-9_]*)\s*:\s*\d+\s*;", line)
            if bit:
                members.add(bit.group(1))
                continue
            # Match the declarator immediately before an optional array and ';'.
            field = re.search(
                r"\b([a-z][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*;",
                line,
            )
            if field:
                members.add(field.group(1))
    return members


def bridge_members(root: Path, targets: list[Path]) -> None:
    members = generated_members(root)
    by_norm: dict[str, set[str]] = {}
    for name in members:
        by_norm.setdefault(norm(name), set()).add(name)

    legacy: set[str] = set()
    # Historical source uses both *_A(...) array helpers and direct
    # SET_REG_{SIGNED,UNSIGNED}(...) helpers. Capture the member-name argument
    # from both forms so imr2yctrl3.c CSP-adjacent functions can be bridged
    # mechanically from the same generated headers as the gamma targets.
    set_reg_arg = re.compile(
        r"imR2yUtils_SET_REG_(?:SIGNED|UNSIGNED)(?:_A)?\s*\("
        r"[^,]+,[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)"
    )
    for path in targets:
        text = path.read_text()
        legacy.update(re.findall(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)", text))
        legacy.update(set_reg_arg.findall(text))

    aliases: dict[str, str] = {}
    ambiguous: list[tuple[str, list[str]]] = []
    for old in sorted(legacy):
        if not any(ch.isupper() for ch in old):
            continue
        candidates = by_norm.get(norm(old), set())
        if len(candidates) == 1:
            new = next(iter(candidates))
            if old != new:
                aliases[old] = new
        elif len(candidates) > 1:
            ambiguous.append((old, sorted(candidates)))

    if ambiguous:
        raise RuntimeError(
            "ambiguous generated R2Y member aliases: "
            + ", ".join(f"{old}->{'/'.join(cands)}" for old, cands in ambiguous)
        )

    required = {
        "F_R2Y": "fR2y",
        "GMRGBFL": "gmrgbfl",
        "GMRGBDF": "gmrgbdf",
        "GMRFL": "gmrfl",
        "GMRDF": "gmrdf",
        "GMGFL": "gmgfl",
        "GMGDF": "gmgdf",
        "GMBFL": "gmbfl",
        "GMBDF": "gmbdf",
        "GMYBFL": "gmybfl",
        "GMYBDF": "gmybdf",
        "EGHWSCL": "eghwscl",
        "EGHWTON": "eghwton",
        "EGMWSCL": "egmwscl",
        "EGMWTON": "egmwton",
        "EGLWSCL": "eglwscl",
        "EGLWTON": "eglwton",
        "EGMPSCL": "egmpscl",
        "CC0K_0_0": "cc0k00",
        "CC0YBGA_0": "cc0ybga0",
    }
    missing = {old: new for old, new in required.items() if aliases.get(old) != new}
    if missing:
        raise RuntimeError(f"required generated R2Y member aliases not derived exactly: {missing}")

    for path in targets:
        text = path.read_text()
        for old, new in sorted(aliases.items(), key=lambda kv: (-len(kv[0]), kv[0])):
            text = re.sub(r"\b" + re.escape(old) + r"\b", new, text)
        path.write_text(text)

    print(f"bridged {len(aliases)} exact generated R2Y member spelling(s)")
    for old, new in sorted(aliases.items()):
        print(f"  {old} -> {new}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        nargs="?",
        default="public-milbeaut/MILB_API",
        help="path to the pinned public MILB_API checkout",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise SystemExit(f"MILB_API root not found: {root}")

    patch_external_compat(root)

    src = root / "Project/ImageMacro/src"
    targets = [
        src / "imr2y.h",
        src / "imr2yutils.h",
        src / "imr2yset.c",
        src / "imr2yctrl2.c",
    ]
    for path in targets:
        if not path.is_file():
            raise SystemExit(f"target source missing: {path}")

    bridge_tags(root, targets)
    bridge_members(root, targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
