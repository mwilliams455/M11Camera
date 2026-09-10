#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

# RENDER1H starts from the Y-referenced RENDER1F path, not from the retired
# RENDER1G chroma-reference diagnostic.  The separate endpoint-semantics proof
# has now closed the Leica KY=8 case to luminance/Y.  This overlay changes only
# the Cat42 per-pixel arithmetic from the continuous diagnostic form to a
# bounded 10-bit/local-Q3 integer implementation.
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

old_block = '''                // RENDER1F CAT42Y1A — bounded Category42 hardware-geometry test.
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
'''

new_block = '''                // RENDER1H CAT42YQ3A — Y endpoint closed; bounded integer-Q3 candidate.
                // Closed for the Leica M11 path by primary firmware + vendor API
                // + all-state geometry:
                //   reference endpoint = luminance/Y because every map uses CSYKY=8
                //   Standard offsets   = 258,588,588,505
                //   Standard gains     = 26,0,-4,-20
                //   Standard borders   = 100,771,922
                //   gain coding        = local Q3 (28/28 generated gain codes)
                // Remaining hardware-internal boundary:
                //   exact 10-bit handoff quantization, equality ownership at the
                //   three border codes, and signed multiply rounding are not
                //   vendor-documented.  The independent 48-variant sweep shows
                //   rounding changes at most one CSY scale code; larger Standard
                //   differences occur only at exact border codes.
                //
                // Candidate convention (explicit, reversible and diagnostic):
                //   * nearest 10-bit code from normalized post-CC1 Y;
                //   * right-open borders (<100, <771, <922);
                //   * local coordinate x-segment_start;
                //   * signed floor-divide by 8, equivalent to arithmetic >>3;
                //   * direct scale code / 512 (the independent register +1
                //     encoding clue remains open and is not silently applied).
                const long cat42_reference_rounded = std::lround(
                        m11::render::clamp01(gammaplace_ycc[0]) * 1023.0);
                const int cat42_reference_code = static_cast<int>(std::max(
                        0L, std::min(1023L, cat42_reference_rounded)));
                cat42_reference_stats.add(
                        static_cast<double>(cat42_reference_code) / 1023.0);

                int cat42_offset = 0;
                int cat42_gain = 0;
                int cat42_origin = 0;
                std::size_t cat42_region = 0;
                if (cat42_reference_code < 100) {
                    cat42_offset = 258;
                    cat42_gain = 26;
                    cat42_origin = 0;
                    cat42_region = 0;
                } else if (cat42_reference_code < 771) {
                    cat42_offset = 588;
                    cat42_gain = 0;
                    cat42_origin = 100;
                    cat42_region = 1;
                } else if (cat42_reference_code < 922) {
                    cat42_offset = 588;
                    cat42_gain = -4;
                    cat42_origin = 771;
                    cat42_region = 2;
                } else {
                    cat42_offset = 505;
                    cat42_gain = -20;
                    cat42_origin = 922;
                    cat42_region = 3;
                }
                ++cat42_region_counts[cat42_region];

                const int cat42_product =
                        cat42_gain * (cat42_reference_code - cat42_origin);
                // Portable floor division by 8.  For negative values this is the
                // same result produced by an arithmetic right shift on the target.
                const int cat42_q3_delta = cat42_product >= 0
                        ? cat42_product / 8
                        : -(((-cat42_product) + 7) / 8);
                const int cat42_scale_code_unclamped = cat42_offset + cat42_q3_delta;
                const int cat42_scale_code = std::max(
                        0, std::min(1023, cat42_scale_code_unclamped));
                const double cat42_scale =
                        static_cast<double>(cat42_scale_code) / 512.0;
'''

src = replace_once(src, old_block, new_block, "RENDER1H integer Cat42 pixel path")
src = replace_once(
    src,
    'report << "schema=m11camera.render1f.cat42y1a.v1\\n";',
    'report << "schema=m11camera.render1h.cat42yq3a.orient1a.v1\\n";',
    "native RENDER1H schema",
)
src = replace_once(
    src,
    'report << "category42HypothesisName=CAT42Y1A\\n";',
    'report << "category42HypothesisName=CAT42YQ3A\\n";',
    "hypothesis name",
)
src = replace_once(
    src,
    'report << "category42ReferenceHypothesis=postCC1_Y_10bit\\n";',
    '''report << "category42ReferenceHypothesis=postCC1_Y_KY8_endpoint_closed\\n";
    report << "category42CsykyEndpoint=8_is_Y_closed_for_M11\\n";
    report << "category42ReferenceQuantization=nearest_10bit_code_bounded\\n";''',
    "Y endpoint provenance",
)
src = replace_once(
    src,
    'report << "category42SegmentAnchoringHypothesis=local_offset\\n";\n    report << "category42FixedPointRoundingImplemented=false\\n";',
    '''report << "category42SegmentAnchoring=local_segment_start\\n";
    report << "category42BorderConvention=right_open_bounded\\n";
    report << "category42SignedQ3Rounding=floor_div8_arithmetic_shift_equivalent\\n";
    report << "category42FixedPointRoundingImplemented=true\\n";
    report << "category42IntegerConventionHardwareExact=false\\n";
    report << "category42RegisterPlusOneScaleSemanticsApplied=false\\n";''',
    "integer convention provenance",
)

for marker in [
    "schema=m11camera.render1h.cat42yq3a.orient1a.v1",
    "category42HypothesisName=CAT42YQ3A",
    "category42ReferenceHypothesis=postCC1_Y_KY8_endpoint_closed",
    "category42CsykyEndpoint=8_is_Y_closed_for_M11",
    "category42ReferenceQuantization=nearest_10bit_code_bounded",
    "category42GainFractionBitsHypothesis=3",
    "category42ScaleDenominatorHypothesis=512",
    "category42SegmentAnchoring=local_segment_start",
    "category42BorderConvention=right_open_bounded",
    "category42SignedQ3Rounding=floor_div8_arithmetic_shift_equivalent",
    "category42FixedPointRoundingImplemented=true",
    "category42IntegerConventionHardwareExact=false",
    "category42RegisterPlusOneScaleSemanticsApplied=false",
    "const int cat42_reference_code",
    "const int cat42_q3_delta",
    "const auto& out = cat42_out;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")
if "postCC1_chroma_chebyshev_2x_10bit" in src or "2x_max_abs_Cb_Cr" in src:
    raise RuntimeError("retired RENDER1G chroma-reference hypothesis leaked into RENDER1H")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1hCat42YQ3ACandidate=true")
print("controlBase=RENDER1E_CHROMANORM1A")
print("referenceEndpoint=Y_KY8_CLOSED_FOR_M11")
print("referenceQuantization=nearest_10bit_code_bounded")
print("integerQ3Applied=true")
print("integerConventionHardwareExact=false")
print("borderConvention=right_open_bounded")
print("signedQ3Rounding=floor_div8_arithmetic_shift_equivalent")
print("registerPlusOneScaleSemanticsApplied=false")
