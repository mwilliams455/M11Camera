#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1e_device_labels.py", run_name="__main__")

PATH = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = PATH.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = replace_once(
    s,
    "M11 RENDER1E CHROMANORM1A candidate action.",
    "M11 RENDER1F CAT42Y1A bounded diagnostic candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1E_CHROMANORM1A"',
    '"_M11_RENDER1F_CAT42Y1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1e.chromanorm1a.device.v1"',
    '"m11camera.render1f.cat42y1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("candidateChromaScale", 1.0);',
    '''diagnostics.put("candidateChromaScale", 1.0);
        diagnostics.put("category42HypothesisApplied", true);
        diagnostics.put("category42HypothesisName", "CAT42Y1A");
        diagnostics.put("category42ReferenceHypothesis", "postCC1_Y_10bit");
        diagnostics.put("category42Csyky", 8);
        diagnostics.put("category42GainFractionBitsHypothesis", 3);
        diagnostics.put("category42ScaleDenominatorHypothesis", 512);
        diagnostics.put("category42SegmentAnchoringHypothesis", "local_offset");
        diagnostics.put("category42FixedPointRoundingImplemented", false);''',
    "CAT42Y1A provenance",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "RENDER1E retains the RENDER1D RGB-common gamma placement and Category13 CC1 clip, but removes only the provisional Standard 1.15x chroma scale; Category42 CsCo arithmetic remains unimplemented and exact Leica runtime gamma placement remains unproven");',
    'diagnostics.put("knownResearchBoundary", "RENDER1F CAT42Y1A keeps RENDER1E gamma/CC1/tone/source calibration fixed and applies only a bounded Category42 transfer-geometry hypothesis: post-CC1 Y reference, Q3 gain and Q9-like scale. Exact CSYKY endpoint, segment arithmetic and fixed-point rounding remain unproven; category42ArithmeticImplemented remains false");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1E CHROMANORM1A complete\\n" +',
    'return "M11 RENDER1F CAT42Y1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Candidate keeps RENDER1D gamma placement and the firmware-defined CC1 clip, but removes only the provisional Standard 1.15x chroma multiplier (candidate scale 1.0); Category42 arithmetic is still not guessed.";',
    '"Bounded diagnostic: RENDER1E is the frozen control; CAT42Y1A applies the recovered Standard offsets/gains/borders as a provisional luma-referenced Q3/Q9 local chroma transfer. This is not yet claimed as Leica-exact.";',
    "completion note",
)

for marker in [
    "m11camera.render1f.cat42y1a.device.v1",
    "_M11_RENDER1F_CAT42Y1A",
    "category42HypothesisApplied",
    "category42HypothesisName",
    "category42ReferenceHypothesis",
    "category42GainFractionBitsHypothesis",
    "category42ScaleDenominatorHypothesis",
    "category42FixedPointRoundingImplemented",
    "M11 RENDER1F CAT42Y1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(s)
print("render1fDeviceLabels=true")
print("outerSchema=m11camera.render1f.cat42y1a.device.v1")
print("candidate=CAT42Y1A")
