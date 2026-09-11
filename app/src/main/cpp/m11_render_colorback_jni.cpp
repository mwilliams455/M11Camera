#include <jni.h>
#include <string>

#include "m11_reference_renderer_core.h"

// COLORBACK1A is a controlled ablation of the recovered Cat42 chroma-
// suppression stage.  It preserves the complete B2RWBPLACE1A raw/WB/AHD path
// and every other Leica table.  Only the final validated renderer call receives
// use_chroma=false so no arbitrary saturation multiplier is introduced.
namespace m11::render {
inline Vec3 renderPixelValidatedColorBack1A(const Vec3& rgb,
                                            const Tables& tables,
                                            RenderConfig config) {
    config.use_chroma = false;
    return renderPixelValidated(rgb, tables, config);
}
}  // namespace m11::render

// Reuse the proven B2RWBPLACE1A implementation byte-for-byte.  Rename its JNI
// export so this translation unit can add an explicit COLORBACK1A diagnostic
// marker while retaining the Java-side method contract.
#define renderPixelValidated renderPixelValidatedColorBack1A
#define Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd \
        Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd_ColorBackBase
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
            Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardB2rWbPlacementFd_ColorBackBase(
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
    diagnostics += "colorBack1a=true\n";
    diagnostics += "cat42ChromaSuppressionApplied=false\n";
    diagnostics += "colorBackMethod=Cat42_controlled_ablation_no_extra_saturation_gain\n";
    jstring patched = env->NewStringUTF(diagnostics.c_str());
    if (patched == nullptr || env->ExceptionCheck()) return result;
    env->SetObjectArrayElement(result, 1, patched);
    return result;
}
