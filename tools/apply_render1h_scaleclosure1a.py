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


# Provenance-only overlay. RENDER1H pixel arithmetic is already materialized by
# the workflow before this script runs. Nothing in the per-pixel implementation
# is replaced here.
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
cpp = replace_once(
    cpp,
    'report << "category42ReferenceQuantization=nearest_10bit_code_bounded\\n";',
    '''report << "category42ReferenceQuantization=nearest_10bit_code_bounded\\n";
    report << "category24ConsumerMappingClosed=true\\n";
    report << "category24Consumer=F_R2Y_YC\\n";
    report << "category24LeicaWrapper=0x0172DFC0\\n";
    report << "category24LeicaSetterCallsite=0x0172E238\\n";
    report << "category24MilbeautSetter=0x01B624AC\\n";
    report << "category42PlacementClosed=true\\n";
    report << "category42Placement=after_Category24_YC_conversion\\n";
    report << "category42YSource=Category24_converted_Y\\n";
    report << "category42MilbeautSetter=0x01B68B80\\n";''',
    "native placement provenance",
)
if "category42ScaleDenominatorHypothesis=512" in cpp:
    raise RuntimeError("stale native scale hypothesis label remains")
for marker in [
    "category42ScaleEncoding=direct_Q9_code_over_512_closed_for_M11",
    "category42ScaleDenominator=512",
    "category42RegisterPlusOneScaleSemanticsApplied=false",
    "category42IntegerConventionHardwareExact=false",
    "category24ConsumerMappingClosed=true",
    "category24Consumer=F_R2Y_YC",
    "category24LeicaWrapper=0x0172DFC0",
    "category24LeicaSetterCallsite=0x0172E238",
    "category24MilbeautSetter=0x01B624AC",
    "category42PlacementClosed=true",
    "category42Placement=after_Category24_YC_conversion",
    "category42YSource=Category24_converted_Y",
    "category42MilbeautSetter=0x01B68B80",
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
    'diagnostics.put("category42ReferenceQuantization", "nearest_10bit_code_bounded");',
    '''diagnostics.put("category42ReferenceQuantization", "nearest_10bit_code_bounded");
        diagnostics.put("category24ConsumerMappingClosed", true);
        diagnostics.put("category24Consumer", "F_R2Y_YC");
        diagnostics.put("category24LeicaWrapper", "0x0172DFC0");
        diagnostics.put("category24LeicaSetterCallsite", "0x0172E238");
        diagnostics.put("category24MilbeautSetter", "0x01B624AC");
        diagnostics.put("category42PlacementClosed", true);
        diagnostics.put("category42Placement", "after_Category24_YC_conversion");
        diagnostics.put("category42YSource", "Category24_converted_Y");
        diagnostics.put("category42MilbeautSetter", "0x01B68B80");''',
    "device placement provenance",
)
java = replace_once(
    java,
    'diagnostics.put("knownResearchBoundary", "RENDER1H closes the Leica CSYKY=8 endpoint to post-CC1 Y and applies the established local-Q3 Standard Cat42 curve with an explicit bounded integer convention. Exact hardware border equality, 10-bit handoff quantization, signed rounding, and the register +1 scale-code clue remain unproven; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    'diagnostics.put("knownResearchBoundary", "SCALECLOSURE1A keeps RENDER1H pixel arithmetic unchanged, closes the recovered M11 CSY scale decoding to direct zero-preserving Q9 code/512, and records the independently proven Category24 F_R2Y.YC consumer plus YC-before-CSP placement; Cat42 therefore references Category24-converted Y. The plateau+1 identity remains a generator/quantization clue and is not applied. Exact hardware border equality, 10-bit handoff quantization, and signed rounding remain undocumented; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    "device research boundary",
)
java = replace_once(
    java,
    '"Bounded candidate: RENDER1E remains the photographic control; CAT42YQ3A uses the closed KY=8 luminance/Y endpoint plus established local-Q3 Standard map. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 are explicit bounded conventions, not claimed as undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
    '"Promoted fidelity candidate: RENDER1H photographic behavior is unchanged. SCALECLOSURE1A records closed direct Q9 code/512 decoding and the closed Category24 YC-before-Category42 CSP placement, with Cat42 using Category24-converted Y. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 remain bounded conventions rather than undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
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
    "category24ConsumerMappingClosed",
    "F_R2Y_YC",
    "category42PlacementClosed",
    "after_Category24_YC_conversion",
    "Category24_converted_Y",
]:
    if marker not in java:
        raise RuntimeError(f"device closure marker missing: {marker}")
JAVA.write_text(java)

print("render1hScaleClosure1A=true")
print("pixelArithmeticChanged=false")
print("scaleEncoding=direct_Q9_code_over_512_closed_for_M11")
print("plateauPlusOneApplied=false")
print("category24ConsumerMappingClosed=true")
print("category24Consumer=F_R2Y_YC")
print("category42PlacementClosed=true")
print("category42Placement=after_Category24_YC_conversion")
print("category42YSource=Category24_converted_Y")
print("remainingIntegerConventionHardwareExact=false")
