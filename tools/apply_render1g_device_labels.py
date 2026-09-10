#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1f_device_labels.py", run_name="__main__")

PATH = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = PATH.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = replace_once(
    s,
    "M11 RENDER1F CAT42Y1A bounded diagnostic candidate action.",
    "M11 RENDER1G CAT42C1A ORIENT1A bounded diagnostic candidate action.",
    "class description",
)
s = replace_once(
    s,
    '"_M11_RENDER1F_CAT42Y1A"',
    '"_M11_RENDER1G_CAT42C1A_ORIENT1A"',
    "output stem",
)
s = replace_once(
    s,
    '"m11camera.render1f.cat42y1a.device.v1"',
    '"m11camera.render1g.cat42c1a.orient1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    'diagnostics.put("category42HypothesisName", "CAT42Y1A");',
    'diagnostics.put("category42HypothesisName", "CAT42C1A");',
    "hypothesis name",
)
s = replace_once(
    s,
    'diagnostics.put("category42ReferenceHypothesis", "postCC1_Y_10bit");',
    '''diagnostics.put("category42ReferenceHypothesis", "postCC1_chroma_chebyshev_2x_10bit");
        diagnostics.put("category42ChromaMetricHypothesis", "2x_max_abs_Cb_Cr");
        diagnostics.put("category42CsykyEndpointHypothesis", "8_is_chroma_endpoint");''',
    "reference provenance",
)

# ORIENT1A: LibRaw dcraw_process() has already honoured the DNG orientation.
# The previous Java rotation therefore applied Orientation=6 twice. Keep the
# native bitmap exactly as returned, but fail closed on expected dimensions so
# this cannot silently mask an orientation regression in LibRaw.
s = replace_once(
    s,
    '''        Bitmap rawBitmap = nativeResult.bitmap;
        Bitmap oriented = applyOrientation(rawBitmap, orientation);
        if (oriented != rawBitmap) rawBitmap.recycle();
''',
    '''        Bitmap rawBitmap = nativeResult.bitmap;
        boolean orientationSwapsAxes = orientation >= 5 && orientation <= 8;
        long expectedNativeWidth = orientationSwapsAxes ? meta.imageHeight : meta.imageWidth;
        long expectedNativeHeight = orientationSwapsAxes ? meta.imageWidth : meta.imageHeight;
        int actualNativeWidth = rawBitmap.getWidth();
        int actualNativeHeight = rawBitmap.getHeight();
        if (actualNativeWidth != expectedNativeWidth || actualNativeHeight != expectedNativeHeight) {
            rawBitmap.recycle();
            throw new IOException("ORIENT1A: LibRaw-oriented bitmap dimensions mismatch: got " +
                    actualNativeWidth + "x" + actualNativeHeight +
                    " expected " + expectedNativeWidth + "x" + expectedNativeHeight +
                    " for TIFF orientation " + orientation);
        }
        Bitmap oriented = rawBitmap;
''',
    "ORIENT1A remove duplicate Java rotation",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "RENDER1F CAT42Y1A keeps RENDER1E gamma/CC1/tone/source calibration fixed and applies only a bounded Category42 transfer-geometry hypothesis: post-CC1 Y reference, Q3 gain and Q9-like scale. Exact CSYKY endpoint, segment arithmetic and fixed-point rounding remain unproven; category42ArithmeticImplemented remains false");',
    '''diagnostics.put("orientationHandledByLibRaw", true);
        diagnostics.put("javaOrientationApplied", false);
        diagnostics.put("orientationDimensionGate", true);
        diagnostics.put("knownResearchBoundary", "RENDER1G CAT42C1A keeps RENDER1E gamma/CC1/tone/source calibration fixed and tests the opposite CSYKY=8 endpoint hypothesis using a bounded post-CC1 chroma proxy (2x max abs Cb/Cr). Exact CSYKY endpoint, chroma magnitude operator, segment arithmetic and fixed-point rounding remain unproven; category42ArithmeticImplemented remains false. ORIENT1A removes the duplicate Java rotation after LibRaw orientation and gates native output dimensions.");''',
    "research boundary and orientation provenance",
)
s = replace_once(
    s,
    'return "M11 RENDER1F CAT42Y1A complete\\n" +',
    'return "M11 RENDER1G CAT42C1A ORIENT1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Bounded diagnostic: RENDER1E is the frozen control; CAT42Y1A applies the recovered Standard offsets/gains/borders as a provisional luma-referenced Q3/Q9 local chroma transfer. This is not yet claimed as Leica-exact.";',
    '"Bounded diagnostic: RENDER1E remains the control; CAT42C1A tests a chroma-referenced Q3/Q9 transfer using the same recovered Standard Category42 map. ORIENT1A trusts LibRaw orientation after a fail-closed dimension check and does not rotate again in Java. Neither CAT42 arithmetic nor CSYKY endpoint is yet claimed Leica-exact.";',
    "completion note",
)

for marker in [
    "m11camera.render1g.cat42c1a.orient1a.device.v1",
    "_M11_RENDER1G_CAT42C1A_ORIENT1A",
    "category42HypothesisName",
    "CAT42C1A",
    "postCC1_chroma_chebyshev_2x_10bit",
    "orientationHandledByLibRaw",
    "javaOrientationApplied",
    "orientationDimensionGate",
    "long expectedNativeWidth",
    "long expectedNativeHeight",
    "actualNativeWidth",
    "actualNativeHeight",
    "M11 RENDER1G CAT42C1A ORIENT1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-patch marker missing: {marker}")
if "applyOrientation(rawBitmap, orientation)" in s:
    raise RuntimeError("ORIENT1A failed: duplicate Java rotation call remains")

PATH.write_text(s)
print("render1gDeviceLabels=true")
print("outerSchema=m11camera.render1g.cat42c1a.orient1a.device.v1")
print("candidate=CAT42C1A_ORIENT1A")
print("orientationHandledByLibRaw=true")
print("javaOrientationApplied=false")
print("orientationDimensionsUseLong=true")
