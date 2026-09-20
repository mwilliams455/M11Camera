#pragma once
#include "m11_reference_renderer_core.h"
// PERF1A: photo-only extraction of the frozen saved-pixel path. No new look math.
namespace m11::production {
inline render::Vec3 savedPixelValidated(const render::Vec3& rgb,const render::Tables& tables) {
    render::RenderConfig config;
    config.mode=render::Mode::Standard;
    config.use_cc0=true; config.use_tone=true;
    // Skip the historical trace's unused CC1 / Y-gamma / placeholder chroma.
    config.use_cc1=false; config.use_gamma=false; config.use_chroma=false; config.clamp=false;
    const auto tr=render::renderPixelTraceValidated(rgb,tables,config);
    m11::render::Vec3 gammaplace_rgb = tr.after_tone;
    for (double& value : gammaplace_rgb) {
        value = m11::render::interpolate(m11::render::clamp01(value), tables.gamma_x, tables.gamma_y);
    }
    auto gammaplace_cc1 = m11::render::multiply(tables.cc1, gammaplace_rgb);
    for (double& value : gammaplace_cc1) value = m11::render::clamp01(value);
    auto gammaplace_ycc = m11::render::multiply(m11::render::kYccMatrix, gammaplace_cc1);
    // Retain exact current CAT42YQ3A arithmetic; silicon-exact status remains false.
    const long cat42_reference_rounded = std::lround(m11::render::clamp01(gammaplace_ycc[0]) * 1023.0);
    const int cat42_reference_code = static_cast<int>(std::max(0L, std::min(1023L, cat42_reference_rounded)));
    int cat42_offset = 0;
    int cat42_gain = 0;
    int cat42_origin = 0;
    if (cat42_reference_code < 100) {
        cat42_offset = 258; cat42_gain = 26; cat42_origin = 0;
    } else if (cat42_reference_code < 771) {
        cat42_offset = 588; cat42_gain = 0; cat42_origin = 100;
    } else if (cat42_reference_code < 922) {
        cat42_offset = 588; cat42_gain = -4; cat42_origin = 771;
    } else {
        cat42_offset = 505; cat42_gain = -20; cat42_origin = 922;
    }
    const int cat42_product = cat42_gain * (cat42_reference_code - cat42_origin);
    const int cat42_q3_delta = cat42_product >= 0 ? cat42_product / 8 : -(((-cat42_product) + 7) / 8);
    const int cat42_scale_code_unclamped = cat42_offset + cat42_q3_delta;
    const int cat42_scale_code = std::max(0, std::min(1023, cat42_scale_code_unclamped));
    const double cat42_scale = static_cast<double>(cat42_scale_code) / 512.0;
    auto cat42_ycc = gammaplace_ycc;
    cat42_ycc[1] *= cat42_scale;
    cat42_ycc[2] *= cat42_scale;
    const auto cat42_out = m11::render::multiply(m11::render::yccInverse(), cat42_ycc);
    render::requireFinite(cat42_out);
    return cat42_out;
}
}
