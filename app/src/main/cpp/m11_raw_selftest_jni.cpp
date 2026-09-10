#include <jni.h>

#include <libraw/libraw.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "m11_fd_datastream.h"
#include "m11_raw_oracle_params.h"

namespace {

constexpr std::int64_t kFixtureSize = 2382;
constexpr unsigned kWidth = 32;
constexpr unsigned kHeight = 32;
constexpr unsigned kFilters = 0xb4b4b4b4u;
constexpr unsigned kBlack = 64;
constexpr unsigned kMaximum = 1023;
constexpr const char *kMake = "Xiaomi";
constexpr const char *kModel = "APK1A Synthetic DNG";
constexpr const char *kDecoder = "packed_dng_load_raw()";

[[noreturn]] void throwState(JNIEnv *env, const std::string &message) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, message.c_str());
    throw message;
}

bool equalsField(const char *value, const char *expected) {
    return value != nullptr && std::strcmp(value, expected) == 0;
}

void appendU32LE(std::vector<std::uint8_t> &out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
}

void appendU16LE(std::vector<std::uint8_t> &out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

std::vector<std::uint8_t> runSyntheticFixture(JNIEnv *env, int source_fd) {
    m11raw::FdDatastream stream(source_fd);
    if (!stream.valid()) throwState(env, "synthetic RAW self-test: invalid fd");
    if (stream.size() != kFixtureSize) throwState(env, "synthetic RAW self-test: fixture size gate failed");

    LibRaw raw;
    int rc = raw.open_datastream(&stream);
    if (rc != LIBRAW_SUCCESS) {
        throwState(env, "synthetic RAW self-test: open_datastream failed: " + std::string(LibRaw::strerror(rc)));
    }

    const std::string runtime = LibRaw::version();
    if (runtime.rfind("0.22.1", 0) != 0)
        throwState(env, "synthetic RAW self-test: LibRaw version gate failed: " + runtime);

    const auto &id = raw.imgdata.idata;
    const auto &sizes = raw.imgdata.sizes;
    const auto &color = raw.imgdata.color;
    libraw_decoder_info_t decoder {};
    if (raw.get_decoder_info(&decoder) != LIBRAW_SUCCESS)
        throwState(env, "synthetic RAW self-test: decoder identity unavailable");

    // CRITICAL SAFETY/PROVENANCE GATE. No unpack/demosaic call is permitted
    // before every identifying property of the generated 32x32 fixture agrees.
    if (!equalsField(id.make, kMake) || !equalsField(id.model, kModel) ||
        id.raw_count != 1 || id.colors != 3 || id.filters != kFilters ||
        sizes.raw_width != kWidth || sizes.raw_height != kHeight ||
        sizes.width != kWidth || sizes.height != kHeight ||
        sizes.left_margin != 0 || sizes.top_margin != 0 ||
        color.black != kBlack || color.maximum != kMaximum ||
        decoder.decoder_name == nullptr || std::strcmp(decoder.decoder_name, kDecoder) != 0) {
        throwState(env, "synthetic RAW self-test: metadata/decoder gate failed; refusing pixel decode");
    }

    rc = raw.unpack();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "synthetic RAW self-test: unpack failed: " + std::string(LibRaw::strerror(rc)));
    if (raw.imgdata.rawdata.raw_image == nullptr)
        throwState(env, "synthetic RAW self-test: flat Bayer buffer unavailable");

    constexpr std::uint32_t mosaic_bytes = kWidth * kHeight * 2u;
    std::vector<std::uint8_t> mosaic;
    mosaic.reserve(mosaic_bytes);
    const std::uint16_t *raw_image = raw.imgdata.rawdata.raw_image;
    for (unsigned y = 0; y < kHeight; ++y) {
        const size_t row = static_cast<size_t>(y) * kWidth;
        for (unsigned x = 0; x < kWidth; ++x) appendU16LE(mosaic, raw_image[row + x]);
    }

    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);
    rc = raw.dcraw_process();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "synthetic RAW self-test: AHD process failed: " + std::string(LibRaw::strerror(rc)));

    int mem_error = LIBRAW_SUCCESS;
    libraw_processed_image_t *image = raw.dcraw_make_mem_image(&mem_error);
    if (image == nullptr || mem_error != LIBRAW_SUCCESS)
        throwState(env, "synthetic RAW self-test: memory image failed");
    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3 ||
        image->width != kWidth || image->height != kHeight) {
        raw.dcraw_clear_mem(image);
        throwState(env, "synthetic RAW self-test: unexpected AHD output geometry/type");
    }

    const std::uint32_t ahd_bytes = static_cast<std::uint32_t>(image->data_size);
    if (ahd_bytes != kWidth * kHeight * 3u * 2u) {
        raw.dcraw_clear_mem(image);
        throwState(env, "synthetic RAW self-test: unexpected AHD byte count");
    }

    std::vector<std::uint8_t> packet;
    packet.reserve(40u + mosaic_bytes + ahd_bytes);
    const std::uint8_t magic[8] = {'M','1','1','R','S','T','1',0};
    packet.insert(packet.end(), std::begin(magic), std::end(magic));
    appendU32LE(packet, mosaic_bytes);
    appendU32LE(packet, ahd_bytes);
    appendU32LE(packet, kWidth);
    appendU32LE(packet, kHeight);
    appendU32LE(packet, image->width);
    appendU32LE(packet, image->height);
    appendU32LE(packet, image->colors);
    appendU32LE(packet, image->bits);
    packet.insert(packet.end(), mosaic.begin(), mosaic.end());

    const auto *pixels = reinterpret_cast<const std::uint16_t *>(image->data);
    const size_t samples = static_cast<size_t>(image->width) * image->height * image->colors;
    for (size_t i = 0; i < samples; ++i) appendU16LE(packet, pixels[i]);

    raw.dcraw_clear_mem(image);
    raw.recycle();
    return packet;
}

} // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_m11_diagnostic_M11RawSelfTestBridge_nativeRunSyntheticFixture(
        JNIEnv *env, jclass /*clazz*/, jint fd) {
    try {
        std::vector<std::uint8_t> packet = runSyntheticFixture(env, static_cast<int>(fd));
        jbyteArray result = env->NewByteArray(static_cast<jsize>(packet.size()));
        if (result == nullptr) return nullptr;
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(packet.size()),
                                reinterpret_cast<const jbyte *>(packet.data()));
        return result;
    } catch (const std::string &) {
        // throwState already installed the Java exception.
        return nullptr;
    } catch (const std::exception &e) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, e.what());
        return nullptr;
    } catch (...) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, "synthetic RAW self-test: unknown native failure");
        return nullptr;
    }
}
