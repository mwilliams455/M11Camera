#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

# Start from RENDER1D so gamma placement and the firmware-defined CC1 clamp
# stay fixed. The only photographic variable in RENDER1E is removal of the
# provisional Standard 1.15x chroma multiplier after YC conversion.
runpy.run_path("tools/apply_render1d_gammaplace1a.py", run_name="__main__")

PATH = Path("app/src/main/cpp/m11_render_jni.cpp")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


src = PATH.read_text()
before = sha256(src)

src = replace_once(
    src,
    '''                const auto gammaplace_mode = m11::render::modeConfig(config.mode);
                gammaplace_ycc[1] *= gammaplace_mode.chroma_scale;
                gammaplace_ycc[2] *= gammaplace_mode.chroma_scale;
                gammaplace_ycc_after_stats.add(gammaplace_ycc);
''',
    '''                // RENDER1E CHROMANORM1A: do not apply the provisional
                // Standard 1.15x chroma multiplier. Category42 arithmetic is
                // still not guessed; this is a bounded neutral-chroma control.
                gammaplace_ycc_after_stats.add(gammaplace_ycc);
''',
    "remove provisional gamma-placement chroma multiplier",
)

src = replace_once(
    src,
    'report << "schema=m11camera.render1d.gammaplace1a.v1\\n";',
    'report << "schema=m11camera.render1e.chromanorm1a.v1\\n";',
    "native RENDER1E schema",
)

src = replace_once(
    src,
    '''    report << "cc1ClipRetained=true\\n";
''',
    '''    report << "cc1ClipRetained=true\\n";
    report << "gammaPlacementRetained=true\\n";
    report << "provisionalStandardChromaScaleRemoved=true\\n";
    report << "priorPlaceholderChromaScale=1.15\\n";
    report << "candidateChromaScale=1.0\\n";
''',
    "RENDER1E provenance",
)

for marker in [
    "schema=m11camera.render1e.chromanorm1a.v1",
    "gammaPlacementChanged=true",
    "gammaPlacementRetained=true",
    "provisionalStandardChromaScaleRemoved=true",
    "priorPlaceholderChromaScale=1.15",
    "candidateChromaScale=1.0",
    "savedBitmapUsesGammaPlaceCandidate=true",
    "cc1ClipRetained=true",
    "category42ArithmeticImplemented=false",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

if "gammaplace_ycc[1] *= gammaplace_mode.chroma_scale" in src:
    raise RuntimeError("provisional chroma scale still present in gamma-placement candidate")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1eChromaNormCandidate=true")
print("gammaPlacementRetained=true")
print("cc1ClipRetained=true")
print("priorPlaceholderChromaScale=1.15")
print("candidateChromaScale=1.0")
print("category42ArithmeticImplemented=false")
