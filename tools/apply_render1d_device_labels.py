#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1c_device_labels.py", run_name="__main__")

PATH = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = PATH.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = replace_once(
    s,
    "M11 RENDER1C CC1CLIP1A candidate action.",
    "M11 RENDER1D GAMMAPLACE1A candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1C_CC1CLIP1A"',
    '"_M11_RENDER1D_GAMMAPLACE1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1c.cc1clip1a.device.v1"',
    '"m11camera.render1d.gammaplace1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("gammaPlacementChanged", false);',
    '''diagnostics.put("gammaPlacementChanged", true);
        diagnostics.put("gammaPlacementBaseline", "Y_after_YC");
        diagnostics.put("gammaPlacementCandidate", "RGB_common_componentwise_after_tone_before_CC1");
        diagnostics.put("gammaCurveChanged", false);
        diagnostics.put("cc1ClipRetained", true);''',
    "gamma placement provenance",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "Category13 CC1 structure, Q9 scale and Leica clip words are closed; exact fixed-point rounding, gamma placement and Category42 CsCo pixel arithmetic remain under investigation");',
    'diagnostics.put("knownResearchBoundary", "RENDER1D directly tests public-Milbeaut gamma hardware order on device; Category13 CC1 clip stays retained; exact Leica runtime gamma placement and Category42 CsCo arithmetic remain unproven");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1C CC1CLIP1A complete\\n" +',
    'return "M11 RENDER1D GAMMAPLACE1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Candidate applies only the firmware-defined post-CC1 [0,4095] clip (normalized [0,1]); gamma placement and Category42 arithmetic remain unchanged.";',
    '"Candidate retains the firmware-defined CC1 clip but moves the exact gamma curve from Y-after-YC to common component-wise RGB after tone and before CC1; Category42 arithmetic remains unchanged.";',
    "completion note",
)

for marker in [
    "m11camera.render1d.gammaplace1a.device.v1",
    "_M11_RENDER1D_GAMMAPLACE1A",
    "gammaPlacementChanged",
    "gammaPlacementBaseline",
    "gammaPlacementCandidate",
    "gammaCurveChanged",
    "cc1ClipRetained",
    "M11 RENDER1D GAMMAPLACE1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(s)
print("render1dDeviceLabels=true")
print("outerSchema=m11camera.render1d.gammaplace1a.device.v1")
print("candidate=GAMMAPLACE1A")
