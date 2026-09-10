#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

runpy.run_path("tools/apply_render1b_stageiso1a.py", run_name="__main__")

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
    '''    Vec01Stats cc1_stats{};
    YccStats ycc_before_stats{};
''',
    '''    Vec01Stats cc1_stats{};
    Vec01Stats cc1_clipped_stats{};
    YccStats cc1clip_ycc_before_stats{};
    YccStats cc1clip_ycc_after_stats{};
    Vec01Stats cc1clip_preclamp_stats{};
    YccStats ycc_before_stats{};
''',
    "CC1 candidate stats declarations",
)

candidate_anchor = '''                no_chroma_preclamp_stats.add(
                        m11::render::multiply(m11::render::yccInverse(), no_chroma_ycc));

                const auto& out = tr.output;
'''
candidate_code = '''                no_chroma_preclamp_stats.add(
                        m11::render::multiply(m11::render::yccInverse(), no_chroma_ycc));

                // RENDER1C CC1CLIP1A: Leica Category 13 is structurally identical
                // to Milbeaut R2yCtrlCc1. All four ISO records use posiDec=0,
                // clipP{R,G,B}=4095 and clipM{R,G,B}=0. In the normalized
                // renderer domain this is a post-CC1 [0,1] clamp before YC.
                m11::render::Vec3 cc1_clipped = tr.after_cc1;
                for (double& value : cc1_clipped) value = m11::render::clamp01(value);
                cc1_clipped_stats.add(cc1_clipped);

                auto cc1_clip_ycc =
                        m11::render::multiply(m11::render::kYccMatrix, cc1_clipped);
                cc1clip_ycc_before_stats.add(cc1_clip_ycc);
                cc1_clip_ycc[0] = m11::render::interpolate(
                        m11::render::clamp01(cc1_clip_ycc[0]),
                        tables.gamma_x, tables.gamma_y);
                const auto cc1_clip_mode = m11::render::modeConfig(config.mode);
                cc1_clip_ycc[1] *= cc1_clip_mode.chroma_scale;
                cc1_clip_ycc[2] *= cc1_clip_mode.chroma_scale;
                cc1clip_ycc_after_stats.add(cc1_clip_ycc);
                const auto cc1_clip_out =
                        m11::render::multiply(m11::render::yccInverse(), cc1_clip_ycc);
                cc1clip_preclamp_stats.add(cc1_clip_out);

                const auto& out = cc1_clip_out;
'''
src = replace_once(src, candidate_anchor, candidate_code, "CC1 clip candidate pixel path")

src = replace_once(
    src,
    'report << "schema=m11camera.render1b.stageiso1a.v1\\n";',
    'report << "schema=m11camera.render1c.cc1clip1a.v1\\n";',
    "native RENDER1C schema",
)

src = replace_once(
    src,
    '''    report << "savedBitmapUsesBaselineStandard=true\\n";
    report << "counterfactualsSavedAsImages=false\\n";
''',
    '''    report << "savedBitmapUsesBaselineStandard=false\\n";
    report << "savedBitmapUsesCc1ClipCandidate=true\\n";
    report << "candidateRendererMathChanged=true\\n";
    report << "cc1ClipApplied=true\\n";
    report << "cc1PosiDec=0\\n";
    report << "cc1MatrixDenominator=512\\n";
    report << "cc1ClipPositiveCode=4095\\n";
    report << "cc1ClipNegativeCode=0\\n";
    report << "cc1ClipCodeBits=12\\n";
    report << "cc1ClipNormalizedMin=0\\n";
    report << "cc1ClipNormalizedMax=1\\n";
    report << "category13SourceSha256=7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb\\n";
    report << "gammaPlacementChanged=false\\n";
    report << "counterfactualsSavedAsImages=false\\n";
''',
    "candidate provenance report",
)

stats_anchor = '''    appendVec01Stats(report, "candidate.noChromaPreClamp", no_chroma_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
'''
stats_new = '''    appendVec01Stats(report, "candidate.noChromaPreClamp", no_chroma_preclamp_stats, total_pixels);
    appendVec01Stats(report, "candidate.afterCC1Clipped", cc1_clipped_stats, total_pixels);
    appendYccStats(report, "candidate.cc1ClipYccBefore", cc1clip_ycc_before_stats, total_pixels);
    appendYccStats(report, "candidate.cc1ClipYccAfter", cc1clip_ycc_after_stats, total_pixels);
    appendVec01Stats(report, "candidate.cc1ClipPreClamp", cc1clip_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
'''
src = replace_once(src, stats_anchor, stats_new, "candidate statistics report")

for marker in [
    "schema=m11camera.render1c.cc1clip1a.v1",
    "savedBitmapUsesCc1ClipCandidate=true",
    "cc1ClipApplied=true",
    "cc1PosiDec=0",
    "cc1MatrixDenominator=512",
    "cc1ClipPositiveCode=4095",
    "cc1ClipNegativeCode=0",
    "category13SourceSha256=7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb",
    "gammaPlacementChanged=false",
    'appendVec01Stats(report, "candidate.afterCC1Clipped"',
    "const auto& out = cc1_clip_out;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("render1cCc1ClipCandidate=true")
print("cc1ClipNormalized=[0,1]")
print("gammaPlacementChanged=false")
print("category42ArithmeticImplemented=false")
