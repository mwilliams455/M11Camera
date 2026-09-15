#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

JAVA = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
GRADLE = Path("app/build.gradle.kts")
MANIFEST = Path("app/src/main/AndroidManifest.xml")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = JAVA.read_text()

# Promotion scope is deliberately narrow. RENDER1H must already be materialized.
for marker in [
    "M11 RENDER1H CAT42YQ3A ORIENT1A bounded integer-Q3 candidate action.",
    '"m11camera.render1h.cat42yq3a.orient1a.device.v1"',
    '"_M11_RENDER1H_CAT42YQ3A_ORIENT1A"',
    "orientationHandledByLibRaw",
    "javaOrientationApplied",
    "category42HypothesisName",
    "CAT42YQ3A",
]:
    if marker not in s:
        raise RuntimeError(f"RENDER1H prerequisite marker missing: {marker}")

s = replace_once(
    s,
    "M11 RENDER1H CAT42YQ3A ORIENT1A bounded integer-Q3 candidate action.",
    "M11 RENDER1I DIRECTK1A canonical cross-camera entry with frozen RENDER1H downstream.",
    "class description",
)

old_entry = '''        double[] cameraToM11 = multiply3x3(\n                M11ReferenceBasisCore.xyzD50ToM11AReferenceWb(), source.cameraToXyzD50);\n'''
new_entry = '''        // DIRECTK1A promotion: Xiaomi characterization/WB ends at scene-referred XYZ D50.\n        // Firmware PCS_TO_INTERNAL K is then the canonical Leica internal-space entry.\n        // The selected static M11 sensor CC0 is intentionally bypassed with identity;\n        // all RENDER1H native/downstream stages remain byte-for-byte unchanged.\n        double[] cameraToNativeInput = M11InternalEntryCore.cameraToInternal(source.cameraToXyzD50);\n        M11ReferenceRendererCore.Tables promotedTables = M11InternalEntryCore.withIdentityCc0(asset.tables);\n'''
s = replace_once(s, old_entry, new_entry, "DIRECT_K entry promotion")

s = replace_once(
    s,
    "nativeResult = M11RenderBridge.renderStandardFd(pfd.getFd(), cameraToM11, asset.tables);",
    "nativeResult = M11RenderBridge.renderStandardFd(pfd.getFd(), cameraToNativeInput, promotedTables);",
    "native render input",
)

s = replace_once(
    s,
    'diagnostics.put("cameraToM11Reference", jsonArray(cameraToM11));',
    '''diagnostics.put("cameraToM11Internal", jsonArray(cameraToNativeInput));\n        diagnostics.put("internalEntry", "firmware_PCS_TO_INTERNAL_K_from_white_balanced_XYZ_D50");\n        diagnostics.put("firmwarePcsToInternalK", jsonArray(M11InternalEntryCore.PCS_TO_INTERNAL));\n        diagnostics.put("cc0Mode", "identity_bypass_equivalent_to_useCc0_false");\n        diagnostics.put("cc0Matrix", jsonArray(M11InternalEntryCore.IDENTITY_CC0));\n        diagnostics.put("identityCc0Bypass", true);\n        diagnostics.put("identityCc0ExactForPureMatrixStage", true);\n        diagnostics.put("m11SensorColorSpecAppliedToXiaomi", false);\n        diagnostics.put("internalEntryPromotion", "DIRECTK1A_CANONICAL");''',
    "entry diagnostics",
)

s = replace_once(
    s,
    '"m11camera.render1h.cat42yq3a.orient1a.device.v1"',
    '"m11camera.render1i.directk1a.device.v1"',
    "outer JSON schema",
)
s = replace_once(
    s,
    '"_M11_RENDER1H_CAT42YQ3A_ORIENT1A"',
    '"_M11_RENDER1I_DIRECTK1A"',
    "output stem",
)
s = replace_once(
    s,
    'diagnostics.put("knownResearchBoundary", "RENDER1H closes the Leica CSYKY=8 endpoint to post-CC1 Y and applies the established local-Q3 Standard Cat42 curve with an explicit bounded integer convention. Exact hardware border equality, 10-bit handoff quantization, signed rounding, and the register +1 scale-code clue remain unproven; category42ArithmeticImplemented remains false as a hardware-exact claim. ORIENT1A stays frozen: LibRaw owns orientation and Java performs only the dimension gate.");',
    'diagnostics.put("knownResearchBoundary", "DIRECTK1A is promoted from four same-DNG Xiaomi device A/B validations (mixed-light portrait, saturated flowers/foliage, ISO2960 indoor skin/neutral/cyan/red, and overcast sky/dense foliage). Cross-camera entry is now Xiaomi WB/characterization -> XYZ D50 -> firmware PCS_TO_INTERNAL K with identity CC0. RENDER1H tone/CC1/gamma/CAT42/orientation/native math remains frozen. CAT42 exact hardware border/quantization/register semantics remain the next renderer research boundary.");',
    "research boundary",
)
s = replace_once(
    s,
    'return "M11 RENDER1H CAT42YQ3A ORIENT1A complete\\n" +',
    'return "M11 RENDER1I DIRECTK1A complete\\n" +',
    "completion title",
)
s = replace_once(
    s,
    '"Bounded candidate: RENDER1E remains the photographic control; CAT42YQ3A uses the closed KY=8 luminance/Y endpoint plus established local-Q3 Standard map. Right-open borders, nearest 10-bit Y re-quantization and signed floor-div8 are explicit bounded conventions, not claimed as undocumented Milbeaut-exact arithmetic. ORIENT1A remains frozen.";',
    '"Canonical entry promoted: Xiaomi WB/characterization -> XYZ D50 -> firmware PCS_TO_INTERNAL K -> frozen RENDER1H downstream. Static M11 sensor CC0 is bypassed with identity; no HDR/local tone mapping/extra WB/OETF/third SRO was added. CAT42 exact hardware arithmetic remains a separate research boundary.";',
    "completion note",
)

# The old cross-camera detour must no longer be reachable from the normal workflow.
for retired in [
    "M11ReferenceBasisCore.xyzD50ToM11AReferenceWb()",
    'diagnostics.put("cameraToM11Reference"',
]:
    if retired in s:
        raise RuntimeError(f"retired internal-entry path still present: {retired}")

for marker in [
    "m11camera.render1i.directk1a.device.v1",
    "_M11_RENDER1I_DIRECTK1A",
    "M11InternalEntryCore.cameraToInternal",
    "M11InternalEntryCore.withIdentityCc0",
    "firmware_PCS_TO_INTERNAL_K_from_white_balanced_XYZ_D50",
    "DIRECTK1A_CANONICAL",
    "identity_bypass_equivalent_to_useCc0_false",
    'm11SensorColorSpecAppliedToXiaomi", false',
    "M11 RENDER1I DIRECTK1A complete",
]:
    if marker not in s:
        raise RuntimeError(f"post-promotion marker missing: {marker}")

JAVA.write_text(s)

g = GRADLE.read_text()
g = replace_once(g, 'applicationId = "com.m11.diagnostic.render1h"', 'applicationId = "com.m11.diagnostic.render1i"', "application id")
g = replace_once(g, 'versionCode = 12', 'versionCode = 13', "version code")
g = replace_once(
    g,
    'versionName = "0.1.11-render1h-cat42yq3a-orient1a"',
    'versionName = "0.1.12-render1i-directk1a"',
    "version name",
)
GRADLE.write_text(g)

m = MANIFEST.read_text()
m = replace_once(m, 'android:label="M11 RENDER1H Cat42YQ3"', 'android:label="M11 RENDER1I DirectK"', "manifest label")
MANIFEST.write_text(m)

print("render1iDirectK1A=true")
print("internalEntry=firmware_PCS_TO_INTERNAL_K_from_white_balanced_XYZ_D50")
print("staticM11SensorCc0Bypassed=true")
print("identityCc0ExactForPureMatrixStage=true")
print("m11SensorColorSpecAppliedToXiaomi=false")
print("downstreamRenderer=RENDER1H_frozen")
print("nativeRendererModified=false")
print("applicationId=com.m11.diagnostic.render1i")
print("versionName=0.1.12-render1i-directk1a")
