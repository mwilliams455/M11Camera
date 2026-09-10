#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

# Start from RENDER1F so the recovered Standard transfer geometry remains
# identical.  RENDER1G changes only the Category42 reference-coordinate
# hypothesis: post-CC1 chroma magnitude rather than post-CC1 Y.
runpy.run_path("tools/apply_render1f_cat42y1a.py", run_name="__main__")

PATH = Path("app/src/main/cpp/m11_render_jni.cpp")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


src = PATH.read_text()
before = sha256(src)

src = replace_once(
    src,
    "RENDER1F CAT42Y1A — bounded Category42 hardware-geometry test.",
    "RENDER1G CAT42C1A — bounded Category42 chroma-reference endpoint test.",
    "candidate comment title",
)
src = replace_once(
    src,
    "* the active 10-bit reference is post-CC1 Y;",
    "* the active 10-bit reference is a post-CC1 chroma-magnitude proxy;",
    "reference hypothesis comment",
)
src = replace_once(
    src,
    '''                const double cat42_reference =
                        m11::render::clamp01(gammaplace_ycc[0]) * 1023.0;
                cat42_reference_stats.add(cat42_reference / 1023.0);
''',
    '''                // Opposite CSYKY=8 endpoint hypothesis to CAT42Y1A.
                // Chroma itself is not yet defined by public Milbeaut material,
                // so use a bounded hardware-cheap proxy: twice the Chebyshev
                // norm of signed Cb/Cr, where nominal component range is +/-0.5.
                // This deliberately tests domain/endpoint selection only; it is
                // NOT a claim that the hardware magnitude operator is known.
                const double cat42_reference_normalized = m11::render::clamp01(
                        2.0 * std::max(std::abs(gammaplace_ycc[1]),
                                       std::abs(gammaplace_ycc[2])));
                const double cat42_reference =
                        cat42_reference_normalized * 1023.0;
                cat42_reference_stats.add(cat42_reference_normalized);
''',
    "CAT42 chroma-reference coordinate",
)
src = replace_once(
    src,
    'report << "schema=m11camera.render1f.cat42y1a.v1\\n";',
    'report << "schema=m11camera.render1g.cat42c1a.orient1a.v1\\n";',
    "native RENDER1G schema",
)
src = replace_once(
    src,
    'report << "category42HypothesisName=CAT42Y1A\\n";',
    'report << "category42HypothesisName=CAT42C1A\\n";',
    "hypothesis name",
)
src = replace_once(
    src,
    'report << "category42ReferenceHypothesis=postCC1_Y_10bit\\n";',
    '''report << "category42ReferenceHypothesis=postCC1_chroma_chebyshev_2x_10bit\\n";
    report << "category42ChromaMetricHypothesis=2x_max_abs_Cb_Cr\\n";
    report << "category42CsykyEndpointHypothesis=8_is_chroma_endpoint\\n";''',
    "reference provenance",
)

for marker in [
    "schema=m11camera.render1g.cat42c1a.orient1a.v1",
    "category42HypothesisName=CAT42C1A",
    "category42ReferenceHypothesis=postCC1_chroma_chebyshev_2x_10bit",
    "category42ChromaMetricHypothesis=2x_max_abs_Cb_Cr",
    "category42CsykyEndpointHypothesis=8_is_chroma_endpoint",
    "category42ArithmeticImplemented=false",
    "category42GainFractionBitsHypothesis=3",
    "category42ScaleDenominatorHypothesis=512",
    "const auto& out = cat42_out;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1gCat42C1ACandidate=true")
print("controlBase=RENDER1E_CHROMANORM1A")
print("gammaPlacementRetained=true")
print("cc1ClipRetained=true")
print("category42HypothesisApplied=true")
print("category42ArithmeticImplemented=false")
print("category42ReferenceHypothesis=postCC1_chroma_chebyshev_2x_10bit")
print("category42ChromaMetricHypothesis=2x_max_abs_Cb_Cr")
