#pragma once

#include <libraw/libraw.h>

namespace m11raw {

// Literal native equivalent of the Params/apply_params path used by
// rawpy 0.27.1 for APK1A's frozen RAW oracle. Keep this function free of
// Xiaomi/M11 colour or tone behavior: it configures LibRaw decode only.
inline void applyRawpy0271OracleParams(libraw_output_params_t &p, bool half_size) {
    p.user_qual = 3;                 // rawpy.DemosaicAlgorithm.AHD
    p.half_size = half_size ? 1 : 0;
    p.four_color_rgb = 0;
    p.dcb_iterations = 0;
    p.dcb_enhance_fl = 0;
    p.fbdd_noiserd = 0;
    p.threshold = 0.0f;
    p.med_passes = 0;

    p.use_camera_wb = 0;
    p.use_auto_wb = 0;
    for (int i = 0; i < 4; ++i) p.user_mul[i] = 1.0f;

    p.output_color = 0;              // rawpy.ColorSpace.raw
    p.output_bps = 16;
    p.user_flip = -1;
    p.user_black = -1;
    // rawpy leaves user_cblack unchanged when user_cblack=None.
    p.user_sat = -1;

    p.no_auto_bright = 1;
    p.no_auto_scale = 0;
    p.auto_bright_thr = LIBRAW_DEFAULT_AUTO_BRIGHTNESS_THRESHOLD;
    p.adjust_maximum_thr = 0.0f;
    p.bright = 1.0f;
    p.highlight = 0;                 // rawpy.HighlightMode.Clip

    p.exp_correc = -1;               // exp_shift=None
    p.exp_shift = 1.0f;
    p.exp_preser = 0.0f;

    p.bad_pixels = nullptr;
    p.gamm[0] = 1.0;                 // rawpy stores 1 / gamma[0]
    p.gamm[1] = 1.0;                 // gamma slope
    p.aber[0] = 1.0;
    // rawpy writes red scale to aber[0] and blue scale to aber[2].
    p.aber[2] = 1.0;
}

} // namespace m11raw
