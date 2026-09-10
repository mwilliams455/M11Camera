#include <jni.h>
#include <android/bitmap.h>

#include <libraw/libraw.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "m11_fd_datastream.h"
#include "m11_raw_oracle_params.h"
#include "m11_reference_renderer_core.h"

namespace {

constexpr unsigned kWidth = 4096;
constexpr unsigned kHeight = 3072;
constexpr unsigned kFilters = 0xb4b4b4b4u;
constexpr unsigned kMaximum = 1023;
constexpr const char *kMake = "Xiaomi";
constexpr const char *kModel = "25010PN30G";
constexpr const char *kDecoder = "packed_dng_load_raw()";

bool equalsField(const char *value, const char *expected) {
    return value != nullptr && std::strcmp(value, expected) == 0;
}

double elapsedMs(std::chrono::steady_clock::time_point start,
                 std::chrono::steady_clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::vector<double> copyArray(JNIEnv *env, jdoubleArray source, jsize expected, const char *name) {
    if (source == nullptr) throw std::invalid_argument(std::string(name) + " == null");
    const jsize count = env->GetArrayLength(source);
    if (count != expected) {
        throw std::invalid_argument(std::string(name) + " length mismatch");
    }
    std::vector<double> out(static_cast<std::size_t>(count));
    env->GetDoubleArrayRegion(source, 0, count, out.data());
    if (env->ExceptionCheck()) throw std::runtime_error(std::string("failed reading ") + name);
    for (double value : out) {
        if (!std::isfinite(value)) throw std::invalid_argument(std::string(name) + " contains non-finite value");
    }
    return out;
}

m11::render::Mat3 toMat3(const std::vector<double>& values) {
    if (values.size() != 9) throw std::invalid_argument("matrix must contain nine values");
    m11::render::Mat3 out{};
    std::copy(values.begin(), values.end(), out.begin());
    return out;
}

m11::render::Tables buildTables(JNIEnv *env,
                                jdoubleArray cc0_array,
                                jdoubleArray cc1_array,
                                jdoubleArray tone_x_array,
                                jdoubleArray tone_flat_array,
                                jdoubleArray gamma_x_array,
                                jdoubleArray gamma_y_array) {
    m11::render::Tables tables;
    tables.cc0 = toMat3(copyArray(env, cc0_array, 9, "CC0"));
    tables.cc1 = toMat3(copyArray(env, cc1_array, 9, "CC1"));
    tables.tone_x = copyArray(env, tone_x_array, 1024, "toneX");
    const auto tone_flat = copyArray(env, tone_flat_array, 7 * 1024, "toneCurvesFlat");
    for (int state = 0; state < 7; ++state) {
        const auto begin = tone_flat.begin() + static_cast<std::ptrdiff_t>(state * 1024);
        tables.tone_curves[static_cast<std::size_t>(state)] =
                std::vector<double>(begin, begin + 1024);
    }
    tables.gamma_x = copyArray(env, gamma_x_array, 4096, "gammaX");
    tables.gamma_y = copyArray(env, gamma_y_array, 4096, "gammaY");
    m11::render::validateTables(tables);
    return tables;
}

jobject createArgb8888Bitmap(JNIEnv *env, int width, int height) {
    jclass bitmap_class = env->FindClass("android/graphics/Bitmap");
    jclass config_class = env->FindClass("android/graphics/Bitmap$Config");
    if (bitmap_class == nullptr || config_class == nullptr) {
        throw std::runtime_error("Android Bitmap classes unavailable");
    }
    jfieldID argb_field = env->GetStaticFieldID(
            config_class, "ARGB_8888", "Landroid/graphics/Bitmap$Config;");
    jmethodID create_method = env->GetStaticMethodID(
            bitmap_class, "createBitmap", "(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;");
    if (argb_field == nullptr || create_method == nullptr) {
        throw std::runtime_error("Android Bitmap API unavailable");
    }
    jobject config = env->GetStaticObjectField(config_class, argb_field);
    jobject bitmap = env->CallStaticObjectMethod(bitmap_class, create_method, width, height, config);
    if (env->ExceptionCheck() || bitmap == nullptr) {
        throw std::runtime_error("Bitmap.createBitmap failed");
    }
    return bitmap;
}

jobject runRender(JNIEnv *env,
                  int source_fd,
                  jdoubleArray camera_to_m11_array,
                  jdoubleArray cc0_array,
                  jdoubleArray cc1_array,
                  jdoubleArray tone_x_array,
                  jdoubleArray tone_flat_array,
                  jdoubleArray gamma_x_array,
                  jdoubleArray gamma_y_array) {
    const auto camera_to_m11 = toMat3(copyArray(env, camera_to_m11_array, 9, "cameraToM11Reference"));
    const auto tables = buildTables(env, cc0_array, cc1_array, tone_x_array,
                                    tone_flat_array, gamma_x_array, gamma_y_array);

    m11raw::FdDatastream stream(source_fd);
    if (!stream.valid()) throw std::runtime_error("RENDER1A: invalid source fd");

    LibRaw raw;
    int rc = raw.open_datastream(&stream);
    if (rc != LIBRAW_SUCCESS) {
        throw std::runtime_error("RENDER1A: open_datastream failed: " + std::string(LibRaw::strerror(rc)));
    }

    const std::string runtime = LibRaw::version();
    if (runtime.rfind("0.22.1", 0) != 0) {
        throw std::runtime_error("RENDER1A: LibRaw version gate failed: " + runtime);
    }

    const auto &id = raw.imgdata.idata;
    const auto &sizes = raw.imgdata.sizes;
    const auto &color = raw.imgdata.color;
    libraw_decoder_info_t decoder{};
    if (raw.get_decoder_info(&decoder) != LIBRAW_SUCCESS) {
        throw std::runtime_error("RENDER1A: decoder identity unavailable");
    }

    // Preserve the existing REALRAW1C promotion boundary exactly.  No pixel is
    // decoded unless the selected file is the already-characterized Xiaomi
    // 15 Ultra 4096x3072 packed DNG class running through pinned LibRaw.
    if (!equalsField(id.make, kMake) || !equalsField(id.model, kModel) ||
        id.raw_count != 1 || id.colors != 3 || id.filters != kFilters ||
        sizes.raw_width != kWidth || sizes.raw_height != kHeight ||
        sizes.width != kWidth || sizes.height != kHeight ||
        sizes.left_margin != 0 || sizes.top_margin != 0 ||
        color.maximum != kMaximum || decoder.decoder_name == nullptr ||
        std::strcmp(decoder.decoder_name, kDecoder) != 0) {
        throw std::runtime_error("RENDER1A: metadata/decoder gate failed; refusing render");
    }

    const auto unpack_start = std::chrono::steady_clock::now();
    rc = raw.unpack();
    const auto unpack_end = std::chrono::steady_clock::now();
    if (rc != LIBRAW_SUCCESS) {
        throw std::runtime_error("RENDER1A: unpack failed: " + std::string(LibRaw::strerror(rc)));
    }

    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);
    const auto ahd_start = std::chrono::steady_clock::now();
    rc = raw.dcraw_process();
    if (rc != LIBRAW_SUCCESS) {
        throw std::runtime_error("RENDER1A: AHD process failed: " + std::string(LibRaw::strerror(rc)));
    }

    int mem_error = LIBRAW_SUCCESS;
    libraw_processed_image_t *image = raw.dcraw_make_mem_image(&mem_error);
    const auto ahd_end = std::chrono::steady_clock::now();
    if (image == nullptr || mem_error != LIBRAW_SUCCESS) {
        throw std::runtime_error("RENDER1A: memory image failed");
    }

    struct ImageGuard {
        LibRaw &raw;
        libraw_processed_image_t *image;
        ~ImageGuard() { if (image != nullptr) raw.dcraw_clear_mem(image); }
    } guard{raw, image};

    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3) {
        throw std::runtime_error("RENDER1A: unexpected AHD output type");
    }
    const std::size_t expected_bytes = static_cast<std::size_t>(image->width) *
            image->height * image->colors * 2u;
    if (image->data_size != expected_bytes) {
        throw std::runtime_error("RENDER1A: unexpected AHD byte count");
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "RENDER1A is defined for little-endian uint16 LibRaw output"
#endif

    jobject bitmap = createArgb8888Bitmap(
            env, static_cast<int>(image->width), static_cast<int>(image->height));
    AndroidBitmapInfo bitmap_info{};
    if (AndroidBitmap_getInfo(env, bitmap, &bitmap_info) != ANDROID_BITMAP_RESULT_SUCCESS ||
        bitmap_info.format != ANDROID_BITMAP_FORMAT_RGBA_8888 ||
        bitmap_info.width != image->width || bitmap_info.height != image->height) {
        throw std::runtime_error("RENDER1A: unexpected Android bitmap layout");
    }

    void *pixels = nullptr;
    if (AndroidBitmap_lockPixels(env, bitmap, &pixels) != ANDROID_BITMAP_RESULT_SUCCESS || pixels == nullptr) {
        throw std::runtime_error("RENDER1A: AndroidBitmap_lockPixels failed");
    }

    const auto render_start = std::chrono::steady_clock::now();
    try {
        const auto *src = reinterpret_cast<const std::uint16_t *>(image->data);
        m11::render::RenderConfig config;
        config.mode = m11::render::Mode::Standard;
        config.use_cc0 = true;
        config.use_tone = true;
        config.use_cc1 = true;
        config.use_gamma = true;
        config.use_chroma = true;
        config.clamp = true;

        constexpr double kU16Norm = 1.0 / 65535.0;
        for (unsigned y = 0; y < image->height; ++y) {
            auto *dst = reinterpret_cast<std::uint8_t *>(pixels) +
                        static_cast<std::size_t>(y) * bitmap_info.stride;
            for (unsigned x = 0; x < image->width; ++x) {
                const std::size_t index = (static_cast<std::size_t>(y) * image->width + x) * 3u;
                const m11::render::Vec3 camera_rgb = {
                        src[index] * kU16Norm,
                        src[index + 1] * kU16Norm,
                        src[index + 2] * kU16Norm};
                const auto m11_rgb = m11::render::multiply(camera_to_m11, camera_rgb);
                const auto out = m11::render::renderPixelValidated(m11_rgb, tables, config);
                dst[x * 4u] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[0]) * 255.0));
                dst[x * 4u + 1] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[1]) * 255.0));
                dst[x * 4u + 2] = static_cast<std::uint8_t>(std::lround(m11::render::clamp01(out[2]) * 255.0));
                dst[x * 4u + 3] = 255;
            }
        }
    } catch (...) {
        AndroidBitmap_unlockPixels(env, bitmap);
        throw;
    }
    const auto render_end = std::chrono::steady_clock::now();
    if (AndroidBitmap_unlockPixels(env, bitmap) != ANDROID_BITMAP_RESULT_SUCCESS) {
        throw std::runtime_error("RENDER1A: AndroidBitmap_unlockPixels failed");
    }

    std::ostringstream report;
    report << "schema=m11camera.render1a.v1\n";
    report << "realXiaomiIdentityGate=true\n";
    report << "librawVersion=" << runtime << "\n";
    report << "decoderName=" << decoder.decoder_name << "\n";
    report << "rawpyOracleParamsApplied=true\n";
    report << "demosaic=AHD\n";
    report << "mode=Standard\n";
    report << "sourceNormalization=rgb16/65535.0\n";
    report << "additionalDownstreamSourceWB=false\n";
    report << "extraOutputOetf=false\n";
    report << "thirdSroApplied=false\n";
    report << "outputWidth=" << image->width << "\n";
    report << "outputHeight=" << image->height << "\n";
    report << "outputBitmap=RGBA_8888\n";
    report << "unpackMs=" << elapsedMs(unpack_start, unpack_end) << "\n";
    report << "ahdMs=" << elapsedMs(ahd_start, ahd_end) << "\n";
    report << "renderMs=" << elapsedMs(render_start, render_end) << "\n";
    report << "m11RendererInvoked=true\n";

    jclass object_class = env->FindClass("java/lang/Object");
    if (object_class == nullptr) throw std::runtime_error("java.lang.Object unavailable");
    jobjectArray result = env->NewObjectArray(2, object_class, nullptr);
    if (result == nullptr) throw std::runtime_error("RENDER1A result allocation failed");
    jstring diagnostics = env->NewStringUTF(report.str().c_str());
    if (diagnostics == nullptr) throw std::runtime_error("RENDER1A diagnostics allocation failed");
    env->SetObjectArrayElement(result, 0, bitmap);
    env->SetObjectArrayElement(result, 1, diagnostics);
    if (env->ExceptionCheck()) throw std::runtime_error("RENDER1A result population failed");
    return result;
}

void throwJavaState(JNIEnv *env, const char *message) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, message);
}

}  // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_m11_diagnostic_M11RenderBridge_nativeRenderRealXiaomiStandardFd(
        JNIEnv *env, jclass /*clazz*/, jint source_fd,
        jdoubleArray camera_to_m11_array,
        jdoubleArray cc0_array,
        jdoubleArray cc1_array,
        jdoubleArray tone_x_array,
        jdoubleArray tone_flat_array,
        jdoubleArray gamma_x_array,
        jdoubleArray gamma_y_array) {
    try {
        return static_cast<jobjectArray>(runRender(
                env, static_cast<int>(source_fd), camera_to_m11_array,
                cc0_array, cc1_array, tone_x_array, tone_flat_array,
                gamma_x_array, gamma_y_array));
    } catch (const std::exception &e) {
        throwJavaState(env, e.what());
        return nullptr;
    } catch (...) {
        throwJavaState(env, "RENDER1A: unknown native failure");
        return nullptr;
    }
}
