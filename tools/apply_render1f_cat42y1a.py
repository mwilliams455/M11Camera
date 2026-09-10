#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

# Start from the visually successful RENDER1E control.  Gamma placement,
# Category13 CC1 clip, tone, source calibration and output encoding stay fixed.
# CAT42Y1A is explicitly a bounded hardware-geometry hypothesis, not a claim
# that the Milbeaut CSP pixel equation has been solved.
runpy.run_path("tools/apply_render1e_chromanorm1a.py", run_name="__main__")

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
    '''    YccStats gammaplace_ycc_after_stats{};
    Vec01Stats gammaplace_preclamp_stats{};
    YccStats ycc_before_stats{};
''',
    '''    YccStats gammaplace_ycc_after_stats{};
    Vec01Stats gammaplace_preclamp_stats{};
    MinMaxStats cat42_reference_stats{};
    MinMaxStats cat42_scale_stats{};
    YccStats cat42_ycc_after_stats{};
    Vec01Stats cat42_preclamp_stats{};
    std::array<std::uint64_t, 4> cat42_region_counts{};
    std::uint64_t cat42_scale_below_unity = 0;
    std::uint64_t cat42_scale_above_unity = 0;
    YccStats ycc_before_stats{};
''',
    "CAT42 diagnostic stats declarations",
)

src = replace_once(
    src,
    '''                gammaplace_ycc_after_stats.add(gammaplace_ycc);
                const auto gammaplace_out =
                        m11::render::multiply(m11::render::yccInverse(), gammaplace_ycc);
                gammaplace_preclamp_stats.add(gammaplace_out);

                const auto& out = gammaplace_out;
''',
    '''                gammaplace_ycc_after_stats.add(gammaplace_ycc);
                const auto gammaplace_out =
                        m11::render::multiply(m11::render::yccInverse(), gammaplace_ycc);
                gammaplace_preclamp_stats.add(gammaplace_out);

                // RENDER1F CAT42Y1A — bounded Category42 hardware-geometry test.
                // Proven firmware/register facts:
                //   Standard offsets = 258,588,588,505
                //   gains            = 26,0,-4,-20
                //   borders          = 100,771,922
                //   CSYKY            = 8
                // Hypotheses being tested (NOT promoted as Leica-exact):
                //   * the active 10-bit reference is post-CC1 Y;
                //   * CSYGA has three fractional bits (gain / 8);
                //   * CSYOF is a Q9-like local chroma scale (code / 512);
                //   * each segment is anchored locally at its CSYOF value.
                // No fixed-point rounding claim is made here: double arithmetic
                // intentionally isolates transfer geometry/domain first.
                const double cat42_reference =
                        m11::render::clamp01(gammaplace_ycc[0]) * 1023.0;
                cat42_reference_stats.add(cat42_reference / 1023.0);

                double cat42_scale_code = 0.0;
                std::size_t cat42_region = 0;
                if (cat42_reference < 100.0) {
                    cat42_scale_code = 258.0 + (26.0 / 8.0) * cat42_reference;
                    cat42_region = 0;
                } else if (cat42_reference < 771.0) {
                    cat42_scale_code = 588.0;
                    cat42_region = 1;
                } else if (cat42_reference < 922.0) {
                    cat42_scale_code =
                            588.0 + (-4.0 / 8.0) * (cat42_reference - 771.0);
                    cat42_region = 2;
                } else {
                    cat42_scale_code =
                            505.0 + (-20.0 / 8.0) * (cat42_reference - 922.0);
                    cat42_region = 3;
                }
                ++cat42_region_counts[cat42_region];

                const double cat42_scale = std::max(
                        0.0, std::min(1023.0, cat42_scale_code)) / 512.0;
                cat42_scale_stats.add(cat42_scale);
                if (cat42_scale < 1.0) ++cat42_scale_below_unity;
                if (cat42_scale > 1.0) ++cat42_scale_above_unity;

                auto cat42_ycc = gammaplace_ycc;
                cat42_ycc[1] *= cat42_scale;
                cat42_ycc[2] *= cat42_scale;
                cat42_ycc_after_stats.add(cat42_ycc);
                const auto cat42_out =
                        m11::render::multiply(m11::render::yccInverse(), cat42_ycc);
                cat42_preclamp_stats.add(cat42_out);

                const auto& out = cat42_out;
''',
    "CAT42 Y-reference candidate pixel path",
)

src = replace_once(
    src,
    'report << "schema=m11camera.render1e.chromanorm1a.v1\\n";',
    'report << "schema=m11camera.render1f.cat42y1a.v1\\n";',
    "native RENDER1F schema",
)

src = replace_once(
    src,
    '''    report << "candidateChromaScale=1.0\\n";
''',
    '''    report << "candidateChromaScale=1.0\\n";
    report << "category42HypothesisApplied=true\\n";
    report << "category42HypothesisName=CAT42Y1A\\n";
    report << "category42ReferenceHypothesis=postCC1_Y_10bit\\n";
    report << "category42Csyky=8\\n";
    report << "category42GainFractionBitsHypothesis=3\\n";
    report << "category42ScaleDenominatorHypothesis=512\\n";
    report << "category42SegmentAnchoringHypothesis=local_offset\\n";
    report << "category42FixedPointRoundingImplemented=false\\n";
    report << "category42StandardOffsets=258,588,588,505\\n";
    report << "category42StandardGains=26,0,-4,-20\\n";
    report << "category42StandardBorders=100,771,922\\n";
''',
    "RENDER1F Category42 provenance",
)

src = replace_once(
    src,
    '''    appendVec01Stats(report, "candidate.gammaPlacePreClamp", gammaplace_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
''',
    '''    appendVec01Stats(report, "candidate.gammaPlacePreClamp", gammaplace_preclamp_stats, total_pixels);
    report << "candidate.cat42.referenceNormalized.min=" << cat42_reference_stats.min << "\\n";
    report << "candidate.cat42.referenceNormalized.max=" << cat42_reference_stats.max << "\\n";
    report << "candidate.cat42.scale.min=" << cat42_scale_stats.min << "\\n";
    report << "candidate.cat42.scale.max=" << cat42_scale_stats.max << "\\n";
    report << "candidate.cat42.scaleBelowUnity=" << cat42_scale_below_unity << "\\n";
    report << "candidate.cat42.scaleBelowUnityPct=" << percent(cat42_scale_below_unity, total_pixels) << "\\n";
    report << "candidate.cat42.scaleAboveUnity=" << cat42_scale_above_unity << "\\n";
    report << "candidate.cat42.scaleAboveUnityPct=" << percent(cat42_scale_above_unity, total_pixels) << "\\n";
    for (std::size_t i = 0; i < cat42_region_counts.size(); ++i) {
        report << "candidate.cat42.region" << i << ".count=" << cat42_region_counts[i] << "\\n";
        report << "candidate.cat42.region" << i << ".pct="
               << percent(cat42_region_counts[i], total_pixels) << "\\n";
    }
    appendYccStats(report, "candidate.cat42YccAfter", cat42_ycc_after_stats, total_pixels);
    appendVec01Stats(report, "candidate.cat42PreClamp", cat42_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
''',
    "CAT42 statistics report",
)

for marker in [
    "schema=m11camera.render1f.cat42y1a.v1",
    "savedBitmapUsesGammaPlaceCandidate=true",
    "gammaPlacementRetained=true",
    "cc1ClipRetained=true",
    "provisionalStandardChromaScaleRemoved=true",
    "candidateChromaScale=1.0",
    "category42ArithmeticImplemented=false",
    "category42HypothesisApplied=true",
    "category42HypothesisName=CAT42Y1A",
    "category42ReferenceHypothesis=postCC1_Y_10bit",
    "category42GainFractionBitsHypothesis=3",
    "category42ScaleDenominatorHypothesis=512",
    "category42FixedPointRoundingImplemented=false",
    'appendVec01Stats(report, "candidate.cat42PreClamp"',
    "const auto& out = cat42_out;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1fCat42Y1ACandidate=true")
print("controlBase=RENDER1E_CHROMANORM1A")
print("gammaPlacementRetained=true")
print("cc1ClipRetained=true")
print("category42HypothesisApplied=true")
print("category42ArithmeticImplemented=false")
print("category42ReferenceHypothesis=postCC1_Y_10bit")
print("category42GainFractionBitsHypothesis=3")
print("category42ScaleDenominatorHypothesis=512")
