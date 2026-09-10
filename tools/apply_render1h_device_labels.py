#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

# Reuse RENDER1G's ORIENT1A device-side fix, then replace only the retired
# chroma-reference labels with the RENDER1H Y/Q3 provenance.
runpy.run_path("tools/apply_render1g_device_labels.py", run_name="__main__")

JAVA = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
GRADLE = Path("app/build.gradle.kts")
MANIFEST = Path("app/src/main/AndroidManifest.xml")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = JAVA.read_text()
s = replace_once(
    s,
    "M11 RENDER1G CAT42C1A ORIENT1A bounded diagnostic candidate action.",
    "M11 RENDER1H CAT42YQ3A ORIENT1A bounded integer-Q3 candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1G_CAT42C1A_ORIENT1A"',
    '"_M11_RENDER1H_CAT42YQ3A_ORIENT1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1g.cat42c1a.orient1a.device.v1"',
    '"m11camera.render1h.cat42yq3a.orient1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("category42HypothesisName", "CAT42C1A");',
    'diagnostics.put("category42HypothesisName", "CAT42YQ3A");',
    "hypothesis name",
)
s = replace_once(
    s,
    '''diagnostics.put("category42ReferenceHypothesis", "postCC1_chroma_chebyshev_2x_10bit");
        diagnostics.put("category42ChromaMetricHypothesis", "2x_max_abs_Cb_Cr");
        diagnostics.put("category42CsykyEndpointHypothesis", "8_is_chroma_endpoint");''',
    '''diagnostics.put("category42ReferenceHypothesis", "postCC1_Y_KY8_endpoint_closed");
        diagnostics.put("category42CsykyEndpoint", "8_is_Y_closed_for_M11");
        diagnostics.put("category42ReferenceQuantization", "nearest_10bit_code_bounded");''',
    "reference provenance",
)
s = replace_once(
    s,
    'diagnostics.put("category42FixedPointRoundingImplemented", false);',
    '''diagnostics.put("category42FixedPointRoundingImplemented", true);
        diagnostics.put("category42IntegerConventionHardwareExact", false);
        diagnostics.put("category42BorderConvention", "right_open_bounded");
        diagnostics.put("category42SignedQ3Rounding", "floor_div8_arithmetic_shift_equivalent");
        diagnostics.put("category42RegisterPlusOneScaleSemanticsApplied", false);''',
    "integer convention provenance",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "RENDER1G CAT42C1A keeps RENDER1E gamma/CC1/tone/source calibration fixed and tests the opposite CSYKY=8 endpoint hypothesis using a bounded post-CC1 chroma proxy (2x max abs Cb/Cr). Exact CSYKY endpoint, chroma magnitude operator, segment arithmetic and fixed-point rounding remain unproven; category42ArithmeticImplemented remains false. ORIENT1A removes the duplicate Java rotation after LibRaw orientation and gates native output dimensions.");',
    'diagnostics.put("knownResearchBoundary", "RENDER1H closes the Leica CSYKY=8 endpoint to post-CC1 Y and applies the established local-Q3 Standard Cat42 curve with an explicit bounded integer convention. Exact hardware border equality, 10-bit handoff quantization, signed rounding, and the register +1 scale-code clue remain unproven; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1G CAT42C1A ORIENT1A complete\\n" +',
    'return "M11 RENDER1H CAT42YQ3A ORIENT1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Bounded diagnostic: RENDER1E remains the control; CAT42C1A tests a chroma-referenced Q3/Q9 transfer using the same recovered Standard Category42 map. ORIENT1A trusts LibRaw orientation after a fail-closed dimension check and does not rotate again in Java. Neither CAT42 arithmetic nor CSYKY endpoint is yet claimed Leica-exact.";',
    '"Bounded candidate: RENDER1E remains the photographic control; CAT42YQ3A uses the closed KY=8 luminance/Y endpoint plus established local-Q3 Standard map. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 are explicit bounded conventions, not claimed as undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
    "completion note",
)

for marker in [
    "m11camera.render1h.cat42yq3a.orient1a.device.v1",
    "_M11_RENDER1H_CAT42YQ3A_ORIENT1A",
    "CAT42YQ3A",
    "postCC1_Y_KY8_endpoint_closed",
    "8_is_Y_closed_for_M11",
    "nearest_10bit_code_bounded",
    "category42IntegerConventionHardwareExact",
    "right_open_bounded",
    "floor_div8_arithmetic_shift_equivalent",
    "category42RegisterPlusOneScaleSemanticsApplied",
    "orientationHandledByLibRaw",
    "javaOrientationApplied",
    "orientationDimensionGate",
    "M11 RENDER1H CAT42YQ3A ORIENT1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")
if "CAT42C1A" in s or "postCC1_chroma_chebyshev_2x_10bit" in s or "2x_max_abs_Cb_Cr" in s:
    raise RuntimeError("retired RENDER1G chroma-reference label leaked into RENDER1H")
if "applyOrientation(rawBitmap, orientation)" in s:
    raise RuntimeError("ORIENT1A regression: duplicate Java orientation call remains")
JAVA.write_text(s)

g = GRADLE.read_text()
g = replace_once(g, 'applicationId = "com.m11.diagnostic.render1g"', 'applicationId = "com.m11.diagnostic.render1h"', "application id")
g = replace_once(g, 'versionCode = 11', 'versionCode = 12', "version code")
g = replace_once(g, 'versionName = "0.1.10-render1g-cat42c1a-orient1a"', 'versionName = "0.1.11-render1h-cat42yq3a-orient1a"', "version name")
GRADLE.write_text(g)

m = MANIFEST.read_text()
m = replace_once(m, 'android:label="M11 RENDER1G Cat42C Orient"', 'android:label="M11 RENDER1H Cat42YQ3"', "manifest label")
MANIFEST.write_text(m)

print("render1hDeviceLabels=true")
print("outerSchema=m11camera.render1h.cat42yq3a.orient1a.device.v1")
print("candidate=CAT42YQ3A_ORIENT1A")
print("applicationId=com.m11.diagnostic.render1h")
print("versionName=0.1.11-render1h-cat42yq3a-orient1a")
print("orientationHandledByLibRaw=true")
print("javaOrientationApplied=false")
