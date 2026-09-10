#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1d_device_labels.py", run_name="__main__")

PATH = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = PATH.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = replace_once(
    s,
    "M11 RENDER1D GAMMAPLACE1A candidate action.",
    "M11 RENDER1E CHROMANORM1A candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1D_GAMMAPLACE1A"',
    '"_M11_RENDER1E_CHROMANORM1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1d.gammaplace1a.device.v1"',
    '"m11camera.render1e.chromanorm1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("cc1ClipRetained", true);',
    '''diagnostics.put("cc1ClipRetained", true);
        diagnostics.put("gammaPlacementRetained", true);
        diagnostics.put("provisionalStandardChromaScaleRemoved", true);
        diagnostics.put("priorPlaceholderChromaScale", 1.15);
        diagnostics.put("candidateChromaScale", 1.0);''',
    "RENDER1E provenance",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "RENDER1D directly tests public-Milbeaut gamma hardware order on device; Category13 CC1 clip stays retained; exact Leica runtime gamma placement and Category42 CsCo arithmetic remain unproven");',
    'diagnostics.put("knownResearchBoundary", "RENDER1E retains the RENDER1D RGB-common gamma placement and Category13 CC1 clip, but removes only the provisional Standard 1.15x chroma scale; Category42 CsCo arithmetic remains unimplemented and exact Leica runtime gamma placement remains unproven");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1D GAMMAPLACE1A complete\\n" +',
    'return "M11 RENDER1E CHROMANORM1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Candidate retains the firmware-defined CC1 clip but moves the exact gamma curve from Y-after-YC to common component-wise RGB after tone and before CC1; Category42 arithmetic remains unchanged.";',
    '"Candidate keeps RENDER1D gamma placement and the firmware-defined CC1 clip, but removes only the provisional Standard 1.15x chroma multiplier (candidate scale 1.0); Category42 arithmetic is still not guessed.";',
    "completion note",
)

for marker in [
    "m11camera.render1e.chromanorm1a.device.v1",
    "_M11_RENDER1E_CHROMANORM1A",
    "gammaPlacementRetained",
    "provisionalStandardChromaScaleRemoved",
    "priorPlaceholderChromaScale",
    "candidateChromaScale",
    "M11 RENDER1E CHROMANORM1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(s)
print("render1eDeviceLabels=true")
print("outerSchema=m11camera.render1e.chromanorm1a.device.v1")
print("candidate=CHROMANORM1A")
