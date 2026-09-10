#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

CPP = Path("app/src/main/cpp/m11_render_jni.cpp")
JAVA = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


cpp = CPP.read_text()
cpp = replace_once(
    cpp,
    '''                //   * direct scale code / 512 (the independent register +1
                //     encoding clue remains open and is not silently applied).''',
    '''                //   * direct zero-preserving Q9 scale code / 512.  This is
                //     closed for the recovered M11 configuration by the sole
                //     saturation-family +10 active-zero map plus binary fixed-
                //     point constraints.  The plateau+1 identity is retained as
                //     a table-generator/quantization clue, not applied to pixels.''',
    "native scale comment",
)
cpp = replace_once(
    cpp,
    'report << "category42ScaleDenominatorHypothesis=512\\n";',
    '''report << "category42ScaleEncoding=direct_Q9_code_over_512_closed_for_M11\\n";
    report << "category42ScaleDenominator=512\\n";''',
    "native scale provenance",
)
if "category42ScaleDenominatorHypothesis=512" in cpp:
    raise RuntimeError("stale native scale hypothesis label remains")
for marker in [
    "category42ScaleEncoding=direct_Q9_code_over_512_closed_for_M11",
    "category42ScaleDenominator=512",
    "category42RegisterPlusOneScaleSemanticsApplied=false",
    "category42IntegerConventionHardwareExact=false",
]:
    if marker not in cpp:
        raise RuntimeError(f"native closure marker missing: {marker}")
CPP.write_text(cpp)

java = JAVA.read_text()
java = replace_once(
    java,
    'diagnostics.put("category42ScaleDenominatorHypothesis", 512);',
    '''diagnostics.put("category42ScaleEncoding", "direct_Q9_code_over_512_closed_for_M11");
        diagnostics.put("category42ScaleDenominator", 512);''',
    "device scale provenance",
)
java = replace_once(
    java,
    'diagnostics.put("knownResearchBoundary", "RENDER1H closes the Leica CSYKY=8 endpoint to post-CC1 Y and applies the established local-Q3 Standard Cat42 curve with an explicit bounded integer convention. Exact hardware border equality, 10-bit handoff quantization, signed rounding, and the register +1 scale-code clue remain unproven; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    'diagnostics.put("knownResearchBoundary", "RENDER1H closes the Leica CSYKY=8 endpoint to post-CC1 Y and closes the recovered M11 CSY scale decoding to direct zero-preserving Q9 code/512. The plateau+1 identity remains a table-generator/quantization clue and is not applied. Exact hardware border equality, 10-bit handoff quantization, and signed rounding remain undocumented; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    "device research boundary",
)
java = replace_once(
    java,
    '"Bounded candidate: RENDER1E remains the photographic control; CAT42YQ3A uses the closed KY=8 luminance/Y endpoint plus established local-Q3 Standard map. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 are explicit bounded conventions, not claimed as undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
    '"Bounded candidate: RENDER1E remains the photographic control; CAT42YQ3A uses the closed KY=8 luminance/Y endpoint, closed direct zero-preserving Q9 scale code/512, and established local-Q3 Standard map. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 remain explicit bounded conventions rather than undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
    "completion provenance",
)
if "category42ScaleDenominatorHypothesis" in java:
    raise RuntimeError("stale device scale hypothesis label remains")
for marker in [
    "category42ScaleEncoding",
    "direct_Q9_code_over_512_closed_for_M11",
    "category42ScaleDenominator",
    "category42RegisterPlusOneScaleSemanticsApplied",
    "category42IntegerConventionHardwareExact",
]:
    if marker not in java:
        raise RuntimeError(f"device closure marker missing: {marker}")
JAVA.write_text(java)

print("render1hScaleClosure1A=true")
print("pixelArithmeticChanged=false")
print("scaleEncoding=direct_Q9_code_over_512_closed_for_M11")
print("plateauPlusOneApplied=false")
print("remainingIntegerConventionHardwareExact=false")
