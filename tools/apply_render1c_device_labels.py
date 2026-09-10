#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1b_device_labels.py", run_name="__main__")

PATH = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = PATH.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = replace_once(
    s,
    "M11 RENDER1B STAGEISO1A diagnostic action.",
    "M11 RENDER1C CC1CLIP1A candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1B_STAGEISO1A"',
    '"_M11_RENDER1C_CC1CLIP1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1b.stageiso1a.device.v1"',
    '"m11camera.render1c.cc1clip1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("rendererMathChangedForHighlightIssue", false);',
    'diagnostics.put("rendererMathChangedForHighlightIssue", true);',
    "candidate math flag",
)
s = replace_once(
    s,
    'diagnostics.put("mode", "Standard");',
    '''diagnostics.put("mode", "Standard");
        diagnostics.put("cc1ClipCandidateApplied", true);
        diagnostics.put("cc1PosiDec", 0);
        diagnostics.put("cc1MatrixDenominator", 512);
        diagnostics.put("cc1ClipPositiveCode", 4095);
        diagnostics.put("cc1ClipNegativeCode", 0);
        diagnostics.put("cc1ClipCodeBits", 12);
        diagnostics.put("cc1ClipNormalized", jsonArray(0, 1));
        diagnostics.put("category13SourceSha256", "7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb");
        diagnostics.put("gammaPlacementChanged", false);
        diagnostics.put("category42ArithmeticImplemented", false);''',
    "candidate provenance fields",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "Category42 identity/register semantics are closed; exact CsCo pixel arithmetic, gamma placement, and fixed-point clamp/rounding remain under investigation");',
    'diagnostics.put("knownResearchBoundary", "Category13 CC1 structure, Q9 scale and Leica clip words are closed; exact fixed-point rounding, gamma placement and Category42 CsCo pixel arithmetic remain under investigation");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1B STAGEISO1A complete\\n" +',
    'return "M11 RENDER1C CC1CLIP1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Diagnostic only: saved Standard baseline preserved; stage counters and no-gamma/no-chroma counterfactual statistics added; no guessed Category42 arithmetic.";',
    '"Candidate applies only the firmware-defined post-CC1 [0,4095] clip (normalized [0,1]); gamma placement and Category42 arithmetic remain unchanged.";',
    "completion note",
)

for marker in [
    "m11camera.render1c.cc1clip1a.device.v1",
    "_M11_RENDER1C_CC1CLIP1A",
    "cc1ClipCandidateApplied",
    "cc1ClipPositiveCode",
    "cc1ClipNegativeCode",
    "gammaPlacementChanged",
    "category42ArithmeticImplemented",
    "M11 RENDER1C CC1CLIP1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(s)
print("render1cDeviceLabels=true")
print("outerSchema=m11camera.render1c.cc1clip1a.device.v1")
print("candidate=CC1CLIP1A")
