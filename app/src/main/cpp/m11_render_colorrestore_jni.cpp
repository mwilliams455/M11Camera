#include <jni.h>
#include <string>

#include "m11_reference_renderer_core.h"

// COLORRESTORE1A is an explicitly empirical diagnostic requested after the
// firmware-faithful Cat42 ablation proved too small to account for the muted
// device output.  It preserves the complete B2RWBPLACE1A + RENDER1H pipeline,
// including Cat42, then expands chroma about the firmware R2Y luma axis.
// Luma coefficients are the recovered Leica/Milbeaut integers:
// Y = (4899 R + 9617 G + 1868 B) / 16384.
namespace m11::render {
inline Vec3 renderPixelValidatedColorRestore1A(const Vec3& rgb,
                                               const Tables& tables,
                                               RenderConfig config) {
    const Vec3 out = renderPixelValidated(rgb, tables, config);
    constexpr double kChromaGain = 1.30;
    constexpr double kYr = 4899.0 / 16384.0;
    constexpr double kYg = 9617.0 / 16384.0;
    constexpr double kYb = 1868.0 / 16384.0;
    const double y = kYr * out[0] + kYg * out[1] + kYb * out[2];
    return {
        y + kChromaGain * (out[0] - y),
        y + kChromaGain * (out[1] - y),
        y + kChromaGain * (out[2] - y)
    };
}
}  // namespace m11::render

// Reuse the proven B2RWBPLACE1A implementation byte-for-byte and intercept only
// its final renderer call.  The original source is therefore not compiled as a
// separate translation unit on this branch.
#define renderPixelValidated renderPixelValidatedColorRestore1A
#define Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd \
        Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd_ColorRestoreBase
#include "m11_render_b2rwb_jni.cpp"
#undef Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd
#undef renderPixelValidated

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd(
        JNIEnv *env, jclass clazz, jint source_fd,
        jdoubleArray camera_to_m11_array,
        jdoubleArray as_shot_neutral_array,
        jdoubleArray cc0_array,
        jdoubleArray cc1_array,
        jdoubleArray tone_x_array,
        jdoubleArray tone_flat_array,
        jdoubleArray gamma_x_array,
        jdoubleArray gamma_y_array) {
    jobjectArray result =
            Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd_ColorRestoreBase(
                    env, clazz, source_fd, camera_to_m11_array, as_shot_neutral_array,
                    cc0_array, cc1_array, tone_x_array, tone_flat_array,
                    gamma_x_array, gamma_y_array);
    if (result == nullptr || env->ExceptionCheck()) return result;

    jstring old_diag = static_cast<jstring>(env->GetObjectArrayElement(result, 1));
    if (old_diag == nullptr || env->ExceptionCheck()) return result;
    const char *chars = env->GetStringUTFChars(old_diag, nullptr);
    if (chars == nullptr || env->ExceptionCheck()) return result;
    std::string diagnostics(chars);
    env->ReleaseStringUTFChars(old_diag, chars);
    diagnostics += "colorRestore1a=true\n";
    diagnostics += "colorRestoreGain=1.30\n";
    diagnostics += "colorRestoreLuma=firmware_4899_9617_1868_div16384\n";
    diagnostics += "cat42ChromaSuppressionApplied=true\n";
    diagnostics += "colorRestoreMethod=post_RENDER1H_luma_preserving_chroma_gain_empirical\n";
    jstring patched = env->NewStringUTF(diagnostics.c_str());
    if (patched == nullptr || env->ExceptionCheck()) return result;
    env->SetObjectArrayElement(result, 1, patched);
    return result;
}
