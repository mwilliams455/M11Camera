#!/usr/bin/env python3
"""Prepare pinned public Milbeaut ImageMacro sources for CSP fingerprinting.

Uses the same mechanical compatibility bridge as the existing R2Y compiler
fingerprint work, but includes imr2yctrl3.c/.h so the Chroma Suppress setter can
be compiled without changing its processing logic.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from prepare_milbeaut_r2y_compile import bridge_members, bridge_tags, patch_external_compat


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default="public-milbeaut/MILB_API")
    args = ap.parse_args()
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
        src / "imr2yctrl3.h",
        src / "imr2yctrl3.c",
    ]
    for path in targets:
        if not path.is_file():
            raise SystemExit(f"target source missing: {path}")

    bridge_tags(root, targets)
    bridge_members(root, targets)
    print("prepared exact pinned imr2yctrl3 CSP source for compile-only fingerprinting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
