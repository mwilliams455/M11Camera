#!/usr/bin/env python3
from pathlib import Path

path = Path("app/src/main/java/com/m11/diagnostic/M11RenderWorkflow.java")
s = path.read_text()
repls = {
    '/** End-to-end controlled Xiaomi DNG -> firmware-gated M11 Standard RENDER1A action. */':
        '/** End-to-end controlled Xiaomi DNG -> M11 RENDER1B STAGEISO1A diagnostic action. */',
    'String stem = "IMG_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + "_M11_STANDARD";':
        'String stem = "IMG_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + "_M11_RENDER1B_STAGEISO1A";',
    'diagnostics.put("schema", "m11camera.render1a.device.v1");':
        'diagnostics.put("schema", "m11camera.render1b.stageiso1a.device.v1");',
    'diagnostics.put("knownResearchBoundary", "Category42 full 44-byte consumer and highlight-range/clamp placement remain under firmware investigation");':
        'diagnostics.put("knownResearchBoundary", "Category42 identity/register semantics are closed; exact CsCo pixel arithmetic, gamma placement, and fixed-point clamp/rounding remain under investigation");',
    'return "M11 RENDER1A Standard complete\\n" +':
        'return "M11 RENDER1B STAGEISO1A complete\\n" +',
    '"Baseline renderer preserved: no HDR, no local tone mapping, no extra WB/OETF, third SRO inactive, no highlight workaround.";':
        '"Diagnostic only: saved Standard baseline preserved; stage counters and no-gamma/no-chroma counterfactual statistics added; no guessed Category42 arithmetic.";'
}
for old, new in repls.items():
    count = s.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match for {old!r}, found {count}")
    s = s.replace(old, new, 1)
path.write_text(s)

checks = [
    'm11camera.render1b.stageiso1a.device.v1',
    '_M11_RENDER1B_STAGEISO1A',
    'M11 RENDER1B STAGEISO1A complete',
    'no guessed Category42 arithmetic',
]
for marker in checks:
    if marker not in s:
        raise RuntimeError(f"missing post-patch marker: {marker}")
print("render1bDeviceLabels=true")
print("outerSchema=m11camera.render1b.stageiso1a.device.v1")
