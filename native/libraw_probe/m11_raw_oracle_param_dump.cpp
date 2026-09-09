#include "m11_raw_oracle_params.h"

#include <iomanip>
#include <iostream>

int main(int argc, char **argv) {
    const bool half = argc > 1 && std::string(argv[1]) == "half";
    LibRaw raw;
    auto &p = raw.imgdata.params;
    m11raw::applyRawpy0271OracleParams(p, half);

    std::cout << std::setprecision(17);
    std::cout << "user_qual=" << p.user_qual << '\n';
    std::cout << "half_size=" << p.half_size << '\n';
    std::cout << "four_color_rgb=" << p.four_color_rgb << '\n';
    std::cout << "dcb_iterations=" << p.dcb_iterations << '\n';
    std::cout << "dcb_enhance_fl=" << p.dcb_enhance_fl << '\n';
    std::cout << "fbdd_noiserd=" << p.fbdd_noiserd << '\n';
    std::cout << "threshold=" << p.threshold << '\n';
    std::cout << "med_passes=" << p.med_passes << '\n';
    std::cout << "use_camera_wb=" << p.use_camera_wb << '\n';
    std::cout << "use_auto_wb=" << p.use_auto_wb << '\n';
    for (int i = 0; i < 4; ++i) std::cout << "user_mul" << i << '=' << p.user_mul[i] << '\n';
    std::cout << "output_color=" << p.output_color << '\n';
    std::cout << "output_bps=" << p.output_bps << '\n';
    std::cout << "user_flip=" << p.user_flip << '\n';
    std::cout << "user_black=" << p.user_black << '\n';
    std::cout << "user_sat=" << p.user_sat << '\n';
    std::cout << "no_auto_bright=" << p.no_auto_bright << '\n';
    std::cout << "no_auto_scale=" << p.no_auto_scale << '\n';
    std::cout << "auto_bright_thr=" << p.auto_bright_thr << '\n';
    std::cout << "adjust_maximum_thr=" << p.adjust_maximum_thr << '\n';
    std::cout << "bright=" << p.bright << '\n';
    std::cout << "highlight=" << p.highlight << '\n';
    std::cout << "exp_correc=" << p.exp_correc << '\n';
    std::cout << "exp_shift=" << p.exp_shift << '\n';
    std::cout << "exp_preser=" << p.exp_preser << '\n';
    std::cout << "bad_pixels_null=" << (p.bad_pixels == nullptr ? 1 : 0) << '\n';
    std::cout << "gamm0=" << p.gamm[0] << '\n';
    std::cout << "gamm1=" << p.gamm[1] << '\n';
    std::cout << "aber0=" << p.aber[0] << '\n';
    std::cout << "aber2=" << p.aber[2] << '\n';
    return 0;
}
