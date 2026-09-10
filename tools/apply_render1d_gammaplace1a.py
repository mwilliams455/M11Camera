#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

# Start from the evidence-supported RENDER1C candidate so the only new variable
# is the placement/domain of Category 15/20 gamma.
runpy.run_path("tools/apply_render1c_cc1clip1a.py", run_name="__main__")

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
    '''    Vec01Stats cc1clip_preclamp_stats{};
    YccStats ycc_before_stats{};
''',
    '''    Vec01Stats cc1clip_preclamp_stats{};
    Vec01Stats gammaplace_after_gamma_stats{};
    Vec01Stats gammaplace_after_cc1_stats{};
    YccStats gammaplace_ycc_before_stats{};
    YccStats gammaplace_ycc_after_stats{};
    Vec01Stats gammaplace_preclamp_stats{};
    YccStats ycc_before_stats{};
''',
    "gamma placement stats declarations",
)

src = replace_once(
    src,
    '''                cc1clip_preclamp_stats.add(cc1_clip_out);

                const auto& out = cc1_clip_out;
''',
    '''                cc1clip_preclamp_stats.add(cc1_clip_out);

                // RENDER1D GAMMAPLACE1A: direct device A/B for the public-Milbeaut
                // hardware-order candidate tested offline in R2.  Move the exact
                // recovered Category 15/20 curve from Y-after-YC to a common
                // component-wise RGB gamma stage after tone and before CC1.
                // Keep the evidence-supported Category13 post-CC1 [0,1] clip and
                // keep the current placeholder Standard chroma scale unchanged.
                m11::render::Vec3 gammaplace_rgb = tr.after_tone;
                for (double& value : gammaplace_rgb) {
                    value = m11::render::interpolate(
                            m11::render::clamp01(value),
                            tables.gamma_x, tables.gamma_y);
                }
                gammaplace_after_gamma_stats.add(gammaplace_rgb);

                auto gammaplace_cc1 =
                        m11::render::multiply(tables.cc1, gammaplace_rgb);
                for (double& value : gammaplace_cc1) {
                    value = m11::render::clamp01(value);
                }
                gammaplace_after_cc1_stats.add(gammaplace_cc1);

                auto gammaplace_ycc =
                        m11::render::multiply(m11::render::kYccMatrix, gammaplace_cc1);
                gammaplace_ycc_before_stats.add(gammaplace_ycc);
                const auto gammaplace_mode = m11::render::modeConfig(config.mode);
                gammaplace_ycc[1] *= gammaplace_mode.chroma_scale;
                gammaplace_ycc[2] *= gammaplace_mode.chroma_scale;
                gammaplace_ycc_after_stats.add(gammaplace_ycc);
                const auto gammaplace_out =
                        m11::render::multiply(m11::render::yccInverse(), gammaplace_ycc);
                gammaplace_preclamp_stats.add(gammaplace_out);

                const auto& out = gammaplace_out;
''',
    "gamma placement candidate pixel path",
)

src = replace_once(
    src,
    'report << "schema=m11camera.render1c.cc1clip1a.v1\\n";',
    'report << "schema=m11camera.render1d.gammaplace1a.v1\\n";',
    "native RENDER1D schema",
)

src = replace_once(
    src,
    '''    report << "savedBitmapUsesBaselineStandard=false\\n";
    report << "savedBitmapUsesCc1ClipCandidate=true\\n";
''',
    '''    report << "savedBitmapUsesBaselineStandard=false\\n";
    report << "savedBitmapUsesCc1ClipCandidate=false\\n";
    report << "savedBitmapUsesGammaPlaceCandidate=true\\n";
''',
    "saved bitmap provenance",
)

src = replace_once(
    src,
    '    report << "gammaPlacementChanged=false\\n";\n',
    '''    report << "gammaPlacementChanged=true\\n";
    report << "gammaPlacementBaseline=Y_after_YC\\n";
    report << "gammaPlacementCandidate=RGB_common_componentwise_after_tone_before_CC1\\n";
    report << "gammaCurveChanged=false\\n";
    report << "cc1ClipRetained=true\\n";
''',
    "gamma placement provenance",
)

src = replace_once(
    src,
    '''    appendVec01Stats(report, "candidate.cc1ClipPreClamp", cc1clip_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
''',
    '''    appendVec01Stats(report, "candidate.cc1ClipPreClamp", cc1clip_preclamp_stats, total_pixels);
    appendVec01Stats(report, "candidate.gammaPlaceAfterGammaRgb", gammaplace_after_gamma_stats, total_pixels);
    appendVec01Stats(report, "candidate.gammaPlaceAfterCC1Clipped", gammaplace_after_cc1_stats, total_pixels);
    appendYccStats(report, "candidate.gammaPlaceYccBefore", gammaplace_ycc_before_stats, total_pixels);
    appendYccStats(report, "candidate.gammaPlaceYccAfter", gammaplace_ycc_after_stats, total_pixels);
    appendVec01Stats(report, "candidate.gammaPlacePreClamp", gammaplace_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
''',
    "gamma placement statistics report",
)

for marker in [
    "schema=m11camera.render1d.gammaplace1a.v1",
    "savedBitmapUsesGammaPlaceCandidate=true",
    "gammaPlacementChanged=true",
    "gammaPlacementBaseline=Y_after_YC",
    "gammaPlacementCandidate=RGB_common_componentwise_after_tone_before_CC1",
    "gammaCurveChanged=false",
    "cc1ClipRetained=true",
    'appendVec01Stats(report, "candidate.gammaPlaceAfterGammaRgb"',
    'appendVec01Stats(report, "candidate.gammaPlacePreClamp"',
    "const auto& out = gammaplace_out;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1dGammaPlaceCandidate=true")
print("baselineGammaPlacement=Y_after_YC")
print("candidateGammaPlacement=RGB_common_componentwise_after_tone_before_CC1")
print("cc1ClipRetained=true")
print("category42ArithmeticImplemented=false")
