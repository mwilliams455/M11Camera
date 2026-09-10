#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

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
    '#include <array>\n#include <chrono>\n#include <cmath>\n#include <cstdint>\n#include <cstring>\n',
    '#include <algorithm>\n#include <array>\n#include <chrono>\n#include <cmath>\n#include <cstdint>\n#include <cstring>\n#include <iomanip>\n#include <limits>\n',
    "diagnostic includes",
)

anchor = '''double elapsedMs(std::chrono::steady_clock::time_point start,
                 std::chrono::steady_clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}
'''
helpers = anchor + r'''
double percent(std::uint64_t count, std::uint64_t total) {
    return total == 0 ? 0.0 :
            (100.0 * static_cast<double>(count) / static_cast<double>(total));
}

struct Scalar01Stats {
    double min = std::numeric_limits<double>::infinity();
    double max = -std::numeric_limits<double>::infinity();
    std::uint64_t below0 = 0;
    std::uint64_t above1 = 0;
    void add(double value) {
        min = std::min(min, value);
        max = std::max(max, value);
        if (value < 0.0) ++below0;
        if (value > 1.0) ++above1;
    }
};

struct Vec01Stats {
    std::array<Scalar01Stats, 3> channel{};
    std::uint64_t anyBelow0 = 0;
    std::uint64_t anyAbove1 = 0;
    std::uint64_t anyOutside01 = 0;
    std::uint64_t allAbove1 = 0;
    void add(const m11::render::Vec3& value) {
        bool below = false;
        bool above = false;
        bool all_above = true;
        for (std::size_t i = 0; i < 3; ++i) {
            channel[i].add(value[i]);
            below = below || value[i] < 0.0;
            above = above || value[i] > 1.0;
            all_above = all_above && value[i] > 1.0;
        }
        if (below) ++anyBelow0;
        if (above) ++anyAbove1;
        if (below || above) ++anyOutside01;
        if (all_above) ++allAbove1;
    }
};

struct MinMaxStats {
    double min = std::numeric_limits<double>::infinity();
    double max = -std::numeric_limits<double>::infinity();
    void add(double value) {
        min = std::min(min, value);
        max = std::max(max, value);
    }
};

struct YccStats {
    MinMaxStats y{};
    MinMaxStats cb{};
    MinMaxStats cr{};
    std::uint64_t yBelow0 = 0;
    std::uint64_t yAbove1 = 0;
    std::uint64_t cbAbsAboveHalf = 0;
    std::uint64_t crAbsAboveHalf = 0;
    void add(const m11::render::Vec3& value) {
        y.add(value[0]);
        cb.add(value[1]);
        cr.add(value[2]);
        if (value[0] < 0.0) ++yBelow0;
        if (value[0] > 1.0) ++yAbove1;
        if (std::abs(value[1]) > 0.5) ++cbAbsAboveHalf;
        if (std::abs(value[2]) > 0.5) ++crAbsAboveHalf;
    }
};

void appendVec01Stats(std::ostringstream& report, const char *prefix,
                      const Vec01Stats& stats, std::uint64_t total) {
    static constexpr const char *names[3] = {"r", "g", "b"};
    for (std::size_t i = 0; i < 3; ++i) {
        report << prefix << "." << names[i] << ".min=" << stats.channel[i].min << "\n";
        report << prefix << "." << names[i] << ".max=" << stats.channel[i].max << "\n";
        report << prefix << "." << names[i] << ".below0=" << stats.channel[i].below0 << "\n";
        report << prefix << "." << names[i] << ".above1=" << stats.channel[i].above1 << "\n";
        report << prefix << "." << names[i] << ".below0Pct="
               << percent(stats.channel[i].below0, total) << "\n";
        report << prefix << "." << names[i] << ".above1Pct="
               << percent(stats.channel[i].above1, total) << "\n";
    }
    report << prefix << ".pixelsAnyBelow0=" << stats.anyBelow0 << "\n";
    report << prefix << ".pixelsAnyAbove1=" << stats.anyAbove1 << "\n";
    report << prefix << ".pixelsAnyOutside01=" << stats.anyOutside01 << "\n";
    report << prefix << ".pixelsAllAbove1=" << stats.allAbove1 << "\n";
    report << prefix << ".pixelsAnyOutside01Pct="
           << percent(stats.anyOutside01, total) << "\n";
}

void appendYccStats(std::ostringstream& report, const char *prefix,
                    const YccStats& stats, std::uint64_t total) {
    report << prefix << ".y.min=" << stats.y.min << "\n";
    report << prefix << ".y.max=" << stats.y.max << "\n";
    report << prefix << ".cb.min=" << stats.cb.min << "\n";
    report << prefix << ".cb.max=" << stats.cb.max << "\n";
    report << prefix << ".cr.min=" << stats.cr.min << "\n";
    report << prefix << ".cr.max=" << stats.cr.max << "\n";
    report << prefix << ".y.below0=" << stats.yBelow0 << "\n";
    report << prefix << ".y.above1=" << stats.yAbove1 << "\n";
    report << prefix << ".cb.absAbove0p5=" << stats.cbAbsAboveHalf << "\n";
    report << prefix << ".cr.absAbove0p5=" << stats.crAbsAboveHalf << "\n";
    report << prefix << ".y.above1Pct=" << percent(stats.yAbove1, total) << "\n";
    report << prefix << ".cb.absAbove0p5Pct="
           << percent(stats.cbAbsAboveHalf, total) << "\n";
    report << prefix << ".cr.absAbove0p5Pct="
           << percent(stats.crAbsAboveHalf, total) << "\n";
}
'''
src = replace_once(src, anchor, helpers, "stats helpers")

src = replace_once(
    src,
    '''    const auto render_start = std::chrono::steady_clock::now();
    try {
''',
    '''    Vec01Stats camera_stats{};
    Vec01Stats m11_input_stats{};
    Vec01Stats cc0_stats{};
    Vec01Stats tone_stats{};
    Vec01Stats cc1_stats{};
    YccStats ycc_before_stats{};
    YccStats ycc_after_stats{};
    Vec01Stats baseline_preclamp_stats{};
    Vec01Stats no_gamma_preclamp_stats{};
    Vec01Stats no_chroma_preclamp_stats{};
    std::uint64_t tone_lookup_below0 = 0;
    std::uint64_t tone_lookup_above1 = 0;
    std::uint64_t gamma_lookup_below0 = 0;
    std::uint64_t gamma_lookup_above1 = 0;

    const auto render_start = std::chrono::steady_clock::now();
    try {
''',
    "stats declarations",
)

src = replace_once(
    src,
    '''        config.use_gamma = true;
        config.use_chroma = true;
        config.clamp = true;
''',
    '''        config.use_gamma = true;
        config.use_chroma = true;
        // Diagnostic-only change: expose unclamped final RGB to statistics.
        // The saved bitmap still applies the exact same clamp01()+lround()
        // quantization as RENDER1A, so baseline output bytes are preserved.
        config.clamp = false;
''',
    "unclamped diagnostic trace",
)

pixel_old = '''                const auto m11_rgb = m11::render::multiply(camera_to_m11, camera_rgb);
                const auto out = m11::render::renderPixelValidated(m11_rgb, tables, config);
                dst[x * 4u] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[0]) * 255.0));
                dst[x * 4u + 1] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[1]) * 255.0));
                dst[x * 4u + 2] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[2]) * 255.0));
'''
pixel_new = '''                const auto m11_rgb = m11::render::multiply(camera_to_m11, camera_rgb);
                const auto tr = m11::render::renderPixelTraceValidated(m11_rgb, tables, config);

                camera_stats.add(camera_rgb);
                m11_input_stats.add(m11_rgb);
                cc0_stats.add(tr.after_cc0);
                tone_stats.add(tr.after_tone);
                cc1_stats.add(tr.after_cc1);
                ycc_before_stats.add(tr.ycc_before);
                ycc_after_stats.add(tr.ycc_after);
                baseline_preclamp_stats.add(tr.output);
                if (tr.tone_luma_input < 0.0) ++tone_lookup_below0;
                if (tr.tone_luma_input > 1.0) ++tone_lookup_above1;
                if (tr.ycc_before[0] < 0.0) ++gamma_lookup_below0;
                if (tr.ycc_before[0] > 1.0) ++gamma_lookup_above1;

                auto no_gamma_ycc = tr.ycc_after;
                no_gamma_ycc[0] = tr.ycc_before[0];
                no_gamma_preclamp_stats.add(
                        m11::render::multiply(m11::render::yccInverse(), no_gamma_ycc));

                auto no_chroma_ycc = tr.ycc_after;
                no_chroma_ycc[1] = tr.ycc_before[1];
                no_chroma_ycc[2] = tr.ycc_before[2];
                no_chroma_preclamp_stats.add(
                        m11::render::multiply(m11::render::yccInverse(), no_chroma_ycc));

                const auto& out = tr.output;
                dst[x * 4u] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[0]) * 255.0));
                dst[x * 4u + 1] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[1]) * 255.0));
                dst[x * 4u + 2] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[2]) * 255.0));
'''
src = replace_once(src, pixel_old, pixel_new, "per-pixel stage trace")

src = replace_once(
    src,
    '    std::ostringstream report;\n    report << "schema=m11camera.render1a.v1\\n";\n',
    '''    const std::uint64_t total_pixels =
            static_cast<std::uint64_t>(image->width) *
            static_cast<std::uint64_t>(image->height);

    std::ostringstream report;
    report << std::setprecision(12);
    report << "schema=m11camera.render1b.stageiso1a.v1\\n";
''',
    "native schema",
)

report_anchor = '''    report << "m11RendererInvoked=true\\n";

    jclass object_class = env->FindClass("java/lang/Object");
'''
report_new = '''    report << "m11RendererInvoked=true\\n";
    report << "stageIsolationOnly=true\\n";
    report << "baselineRendererMathChanged=false\\n";
    report << "savedBitmapUsesBaselineStandard=true\\n";
    report << "counterfactualsSavedAsImages=false\\n";
    report << "counterfactualNoGamma=gammaYBypassedFromBaselineYccTrace\\n";
    report << "counterfactualNoChroma=standardChromaScaleBypassedFromBaselineYccTrace\\n";
    report << "category42ConsumerIdentity=PRIMARY_CsCo_ChromaSuppress\\n";
    report << "category42ArithmeticImplemented=false\\n";
    report << "pixelCount=" << total_pixels << "\\n";
    report << "toneLookup.below0=" << tone_lookup_below0 << "\\n";
    report << "toneLookup.above1=" << tone_lookup_above1 << "\\n";
    report << "toneLookup.above1Pct=" << percent(tone_lookup_above1, total_pixels) << "\\n";
    report << "gammaLookup.below0=" << gamma_lookup_below0 << "\\n";
    report << "gammaLookup.above1=" << gamma_lookup_above1 << "\\n";
    report << "gammaLookup.above1Pct=" << percent(gamma_lookup_above1, total_pixels) << "\\n";

    appendVec01Stats(report, "stage.cameraRgb", camera_stats, total_pixels);
    appendVec01Stats(report, "stage.m11Input", m11_input_stats, total_pixels);
    appendVec01Stats(report, "stage.afterCC0", cc0_stats, total_pixels);
    appendVec01Stats(report, "stage.afterTone", tone_stats, total_pixels);
    appendVec01Stats(report, "stage.afterCC1", cc1_stats, total_pixels);
    appendYccStats(report, "stage.yccBefore", ycc_before_stats, total_pixels);
    appendYccStats(report, "stage.yccAfter", ycc_after_stats, total_pixels);
    appendVec01Stats(report, "candidate.baselinePreClamp", baseline_preclamp_stats, total_pixels);
    appendVec01Stats(report, "candidate.noGammaPreClamp", no_gamma_preclamp_stats, total_pixels);
    appendVec01Stats(report, "candidate.noChromaPreClamp", no_chroma_preclamp_stats, total_pixels);

    jclass object_class = env->FindClass("java/lang/Object");
'''
src = replace_once(src, report_anchor, report_new, "diagnostic report")

src = src.replace("RENDER1A:", "RENDER1B:")
src = src.replace('"RENDER1A is defined for little-endian uint16 LibRaw output"',
                  '"RENDER1B is defined for little-endian uint16 LibRaw output"')

for marker in [
    "schema=m11camera.render1b.stageiso1a.v1",
    "baselineRendererMathChanged=false",
    "candidate.baselinePreClamp",
    "candidate.noGammaPreClamp",
    "candidate.noChromaPreClamp",
    "category42ArithmeticImplemented=false",
    "config.clamp = false;",
]:
    if marker not in src:
        raise RuntimeError(f"post-patch marker missing: {marker}")

PATH.write_text(src)
after = sha256(src)
print(f"path={PATH}")
print(f"beforeSha256={before}")
print(f"afterSha256={after}")
print("stageIsolationOnly=true")
print("baselineRendererMathChanged=false")
