#!/usr/bin/env python3
"""Prepare the pinned Milbeaut R2Y RDMA variant for compiler fingerprinting.

This helper runs *after* prepare_milbeaut_r2y_compile.py.  It bridges only
mechanical RDMA refactor drift that is independently recoverable from the same
pinned public tree:

* legacy T_IM_RDMA_CTRL / field / enum spellings -> refactored ImRdmaCtrl API;
* R2Y RDMA address arrays that old source still references directly but the
  refactor moved into utility translation units as file-static definitions.

The address declarations are derived from those exact `static const`
definitions.  No address values, array layouts, or R2Y processing logic are
synthesized or changed.  The resulting objects are compile-only forensic
inputs; relocations remain masked by the fingerprint matcher.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def validate_rdma_api(src: Path) -> None:
    header = src / "imrdma.h"
    if not header.is_file():
        raise RuntimeError(f"missing pinned RDMA header: {header}")
    text = header.read_text(errors="ignore")
    required = [
        "} ImRdmaCtrl;",
        "transferByte;",
        "regAddrTblAddr;",
        "regDataTopAddr;",
        "reqThreshold;",
        "pCallBack;",
        "ImRdma_PRCH_CNT_NOLIMIT  = 0",
    ]
    missing = [token for token in required if token not in text]
    if missing:
        raise RuntimeError(f"pinned ImRdmaCtrl evidence missing: {missing}")


def bridge_legacy_rdma_names(src: Path, targets: list[Path]) -> None:
    validate_rdma_api(src)

    utils_h = src / "imr2yutils.h"
    text = utils_h.read_text()
    if '#include "imrdma.h"' not in text:
        anchor = '#include "imr2y.h"\n'
        if anchor not in text:
            raise RuntimeError("expected imr2y.h include anchor missing in imr2yutils.h")
        text = text.replace(anchor, anchor + '#include "imrdma.h"\n', 1)
        utils_h.write_text(text)

    aliases = {
        "T_IM_RDMA_CTRL": "ImRdmaCtrl",
        "E_IM_RDMA_PRCH_CNT_NOLIMIT": "ImRdma_PRCH_CNT_NOLIMIT",
        "reg_addr_tbl_addr": "regAddrTblAddr",
        "reg_data_top_addr": "regDataTopAddr",
        "transfer_byte": "transferByte",
        "req_threshold": "reqThreshold",
        "int_mode": "intMode",
    }
    counts = {old: 0 for old in aliases}
    for path in targets:
        text = path.read_text()
        for old, new in aliases.items():
            n = len(re.findall(r"\b" + re.escape(old) + r"\b", text))
            if n:
                text = re.sub(r"\b" + re.escape(old) + r"\b", new, text)
                counts[old] += n
        path.write_text(text)

    if counts["T_IM_RDMA_CTRL"] == 0:
        raise RuntimeError("legacy T_IM_RDMA_CTRL was not present in RDMA target sources")
    if counts["E_IM_RDMA_PRCH_CNT_NOLIMIT"] == 0:
        raise RuntimeError("legacy RDMA threshold enum was not present in target sources")

    print("bridged pinned RDMA API spellings:")
    for old, new in aliases.items():
        if counts[old]:
            print(f"  {old} -> {new} ({counts[old]} use(s))")


def collect_static_r2y_arrays(src: Path) -> dict[str, tuple[str, str, Path]]:
    # Recover exact declaration type and array dimension from the pinned source.
    # These definitions were made file-static by the ETK refactor even though
    # imr2yset.c/imr2yctrl2.c still retain the older direct references.
    pat = re.compile(
        r"\bstatic\s+const\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)\s+"
        r"(gIM_R2Y_[A-Za-z0-9_]+)\s*"
        r"(\[[^\]]+\])\s*=",
        re.MULTILINE,
    )
    out: dict[str, tuple[str, str, Path]] = {}
    for path in sorted(src.glob("*.c")):
        text = path.read_text(errors="ignore")
        for typ, name, dim in pat.findall(text):
            row = (typ, dim, path)
            old = out.get(name)
            if old is not None and old[:2] != row[:2]:
                raise RuntimeError(
                    f"ambiguous pinned RDMA address definition {name}: "
                    f"{old[0]}{old[1]} vs {typ}{dim}"
                )
            out[name] = row
    return out


def bridge_moved_static_address_arrays(src: Path, targets: list[Path]) -> None:
    definitions = collect_static_r2y_arrays(src)
    if not definitions:
        raise RuntimeError("no pinned static gIM_R2Y address arrays discovered")

    total = 0
    for path in targets:
        if path.suffix != ".c":
            continue
        text = path.read_text()
        refs = sorted(set(re.findall(r"\bgIM_R2Y_[A-Za-z0-9_]+\b", text)))
        local_defs = set(
            re.findall(
                r"\b(?:static\s+)?const\s+[A-Za-z_][A-Za-z0-9_]*\s+"
                r"(gIM_R2Y_[A-Za-z0-9_]+)\s*\[",
                text,
            )
        )
        moved = [name for name in refs if name not in local_defs and name in definitions]
        if not moved:
            continue

        declarations = []
        for name in moved:
            typ, dim, owner = definitions[name]
            declarations.append(
                f"extern const {typ} {name}{dim}; /* pinned definition: {owner.name} */"
            )

        marker = "/* R2A_COMPILE_ONLY_MOVED_RDMA_ARRAY_DECLS */"
        if marker in text:
            raise RuntimeError(f"RDMA moved-array bridge already present in {path}")
        matches = list(re.finditer(r"^#include[^\n]*\n", text, flags=re.MULTILINE))
        if not matches:
            raise RuntimeError(f"no include block found in {path}")
        pos = matches[-1].end()
        block = "\n" + marker + "\n" + "\n".join(declarations) + "\n\n"
        text = text[:pos] + block + text[pos:]
        path.write_text(text)
        total += len(moved)

        print(f"bridged {len(moved)} moved static RDMA address array(s) in {path.name}")
        for name in moved:
            typ, dim, owner = definitions[name]
            print(f"  {name}: extern const {typ}{dim} from {owner.name}")

    # All symbols that caused the first exact-RDMA compile failure must be
    # derivable from pinned definitions.  This is a guard against silently
    # inventing a declaration when the public tree does not support it.
    required = {
        "gIM_R2Y_CC0_Addr",
        "gIM_R2Y_CC0_COEF_Addr",
        "gIM_R2Y_CC1_Addr",
        "gIM_R2Y_CC1_COEF_Addr",
        "gIM_R2Y_EGHWSCL_Tbl_Addr",
        "gIM_R2Y_EGHWTON_Tbl_Addr",
        "gIM_R2Y_EGLWSCL_Tbl_Addr",
        "gIM_R2Y_EGLWTON_Tbl_Addr",
        "gIM_R2Y_EGMPSCL_Tbl_Addr",
        "gIM_R2Y_EGMWSCL_Tbl_Addr",
        "gIM_R2Y_EGMWTON_Tbl_Addr",
        "gIM_R2Y_GAMMA_Addr",
        "gIM_R2Y_GMBDF_Tbl_Addr",
        "gIM_R2Y_GMBFL_Tbl_Addr",
        "gIM_R2Y_GMGDF_Tbl_Addr",
        "gIM_R2Y_GMGFL_Tbl_Addr",
        "gIM_R2Y_GMRDF_Tbl_Addr",
        "gIM_R2Y_GMRFL_Tbl_Addr",
        "gIM_R2Y_GMRGBDF_Tbl_Addr",
        "gIM_R2Y_GMRGBFL_Tbl_Addr",
        "gIM_R2Y_GMYBDF_Tbl_Addr",
        "gIM_R2Y_GMYBFL_Tbl_Addr",
        "gIM_R2Y_WB_CLIP_Addr",
        "gIM_R2Y_YCC_Addr",
        "gIM_R2Y_YNR_Addr",
    }
    missing = sorted(required - definitions.keys())
    if missing:
        raise RuntimeError(f"required pinned moved RDMA arrays not recovered: {missing}")
    if total < len(required):
        raise RuntimeError(
            f"only {total} moved RDMA declarations injected; expected at least {len(required)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        nargs="?",
        default="public-milbeaut/MILB_API",
        help="path to the pinned public MILB_API checkout after the base bridge",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    src = root / "Project/ImageMacro/src"
    if not src.is_dir():
        raise SystemExit(f"ImageMacro source root not found: {src}")

    targets = [src / "imr2yutils.h", src / "imr2yset.c", src / "imr2yctrl2.c"]
    for path in targets:
        if not path.is_file():
            raise SystemExit(f"RDMA target missing: {path}")

    bridge_legacy_rdma_names(src, targets)
    bridge_moved_static_address_arrays(src, targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
