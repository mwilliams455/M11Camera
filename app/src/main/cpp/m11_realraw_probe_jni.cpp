#include <jni.h>

#include <libraw/libraw.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <sstream>
#include <string>

#include "m11_fd_datastream.h"
#include "m11_raw_oracle_params.h"

namespace {

constexpr unsigned kWidth = 4096;
constexpr unsigned kHeight = 3072;
constexpr unsigned kFilters = 0xb4b4b4b4u;
constexpr unsigned kMaximum = 1023;
constexpr const char *kMake = "Xiaomi";
constexpr const char *kModel = "25010PN30G";
constexpr const char *kDecoder = "packed_dng_load_raw()";

[[noreturn]] void throwState(JNIEnv *env, const std::string &message) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, message.c_str());
    throw message;
}

bool equalsField(const char *value, const char *expected) {
    return value != nullptr && std::strcmp(value, expected) == 0;
}

class Sha256 {
public:
    Sha256() { reset(); }

    void update(const std::uint8_t *data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            block_[block_len_++] = data[i];
            if (block_len_ == 64) {
                transform();
                bit_len_ += 512;
                block_len_ = 0;
            }
        }
    }

    void updateU16LE(std::uint16_t value) {
        const std::uint8_t b[2] = {
            static_cast<std::uint8_t>(value & 0xffu),
            static_cast<std::uint8_t>((value >> 8) & 0xffu)
        };
        update(b, 2);
    }

    std::string finishHex() {
        std::uint32_t i = block_len_;
        if (block_len_ < 56) {
            block_[i++] = 0x80;
            while (i < 56) block_[i++] = 0;
        } else {
            block_[i++] = 0x80;
            while (i < 64) block_[i++] = 0;
            transform();
            std::memset(block_.data(), 0, 56);
        }

        bit_len_ += static_cast<std::uint64_t>(block_len_) * 8u;
        for (int shift = 56, pos = 56; shift >= 0; shift -= 8, ++pos)
            block_[static_cast<std::size_t>(pos)] = static_cast<std::uint8_t>((bit_len_ >> shift) & 0xffu);
        transform();

        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (std::uint32_t v : state_) out << std::setw(8) << v;
        return out.str();
    }

private:
    static constexpr std::array<std::uint32_t, 64> k_ = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    std::array<std::uint8_t, 64> block_ {};
    std::array<std::uint32_t, 8> state_ {};
    std::uint32_t block_len_ = 0;
    std::uint64_t bit_len_ = 0;

    static std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
        return (x >> n) | (x << (32u - n));
    }

    void reset() {
        block_len_ = 0;
        bit_len_ = 0;
        state_ = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                  0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    }

    void transform() {
        std::uint32_t m[64];
        for (int i = 0; i < 16; ++i) {
            const int j = i * 4;
            m[i] = (static_cast<std::uint32_t>(block_[j]) << 24) |
                   (static_cast<std::uint32_t>(block_[j + 1]) << 16) |
                   (static_cast<std::uint32_t>(block_[j + 2]) << 8) |
                   static_cast<std::uint32_t>(block_[j + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            const std::uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        std::uint32_t a=state_[0], b=state_[1], c=state_[2], d=state_[3];
        std::uint32_t e=state_[4], f=state_[5], g=state_[6], h=state_[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t t1 = h + s1 + ch + k_[i] + m[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }
};

struct SampleStats {
    std::uint64_t count = 0;
    std::uint64_t sum = 0;
    std::uint64_t at_or_below_black = 0;
    std::uint64_t at_or_above_maximum = 0;
    std::uint16_t minimum = 65535;
    std::uint16_t maximum = 0;

    void add(std::uint16_t v, unsigned black, unsigned saturation) {
        ++count;
        sum += v;
        if (v < minimum) minimum = v;
        if (v > maximum) maximum = v;
        if (v <= black) ++at_or_below_black;
        if (v >= saturation) ++at_or_above_maximum;
    }
};

double elapsedMs(std::chrono::steady_clock::time_point start,
                 std::chrono::steady_clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::string runRealXiaomiProbe(JNIEnv *env, int source_fd) {
    m11raw::FdDatastream stream(source_fd);
    if (!stream.valid()) throwState(env, "real Xiaomi RAW probe: invalid fd");

    LibRaw raw;
    int rc = raw.open_datastream(&stream);
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "real Xiaomi RAW probe: open_datastream failed: " + std::string(LibRaw::strerror(rc)));

    const std::string runtime = LibRaw::version();
    if (runtime.rfind("0.22.1", 0) != 0)
        throwState(env, "real Xiaomi RAW probe: LibRaw version gate failed: " + runtime);

    const auto &id = raw.imgdata.idata;
    const auto &sizes = raw.imgdata.sizes;
    const auto &color = raw.imgdata.color;
    libraw_decoder_info_t decoder {};
    if (raw.get_decoder_info(&decoder) != LIBRAW_SUCCESS)
        throwState(env, "real Xiaomi RAW probe: decoder identity unavailable");

    // REAL-DNG PROMOTION GATE. This is intentionally narrower than generic LibRaw:
    // only the Xiaomi 15 Ultra DNG shape already observed in identify-only testing
    // may proceed to pixel decode. The existing identify JNI remains decode-free.
    if (!equalsField(id.make, kMake) || !equalsField(id.model, kModel) ||
        id.raw_count != 1 || id.colors != 3 || id.filters != kFilters ||
        sizes.raw_width != kWidth || sizes.raw_height != kHeight ||
        sizes.width != kWidth || sizes.height != kHeight ||
        sizes.left_margin != 0 || sizes.top_margin != 0 ||
        color.maximum != kMaximum ||
        decoder.decoder_name == nullptr || std::strcmp(decoder.decoder_name, kDecoder) != 0) {
        throwState(env, "real Xiaomi RAW probe: metadata/decoder gate failed; refusing pixel decode");
    }

    const unsigned pre_black = color.black;
    const unsigned pre_maximum = color.maximum;
    const auto unpack_start = std::chrono::steady_clock::now();
    rc = raw.unpack();
    const auto unpack_end = std::chrono::steady_clock::now();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "real Xiaomi RAW probe: unpack failed: " + std::string(LibRaw::strerror(rc)));
    if (raw.imgdata.rawdata.raw_image == nullptr)
        throwState(env, "real Xiaomi RAW probe: flat Bayer buffer unavailable");

    const unsigned post_black = raw.imgdata.color.black;
    const unsigned post_maximum = raw.imgdata.color.maximum;
    const std::uint16_t *raw_image = raw.imgdata.rawdata.raw_image;
    Sha256 mosaic_hash;
    SampleStats mosaic_stats;
    for (unsigned y = 0; y < kHeight; ++y) {
        const std::size_t row = static_cast<std::size_t>(y) * kWidth;
        for (unsigned x = 0; x < kWidth; ++x) {
            const std::uint16_t v = raw_image[row + x];
            mosaic_hash.updateU16LE(v);
            mosaic_stats.add(v, post_black, post_maximum);
        }
    }
    const std::string mosaic_sha = mosaic_hash.finishHex();

    // Frozen rawpy 0.27.1 / LibRaw 0.22.1 oracle parameters. Long edge is 4096,
    // therefore the frozen >6000 half-size policy resolves to full-resolution AHD.
    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);
    const auto ahd_start = std::chrono::steady_clock::now();
    rc = raw.dcraw_process();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "real Xiaomi RAW probe: AHD process failed: " + std::string(LibRaw::strerror(rc)));

    int mem_error = LIBRAW_SUCCESS;
    libraw_processed_image_t *image = raw.dcraw_make_mem_image(&mem_error);
    const auto ahd_end = std::chrono::steady_clock::now();
    if (image == nullptr || mem_error != LIBRAW_SUCCESS)
        throwState(env, "real Xiaomi RAW probe: memory image failed");
    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3) {
        raw.dcraw_clear_mem(image);
        throwState(env, "real Xiaomi RAW probe: unexpected AHD output type");
    }
    if (image->data_size != static_cast<std::size_t>(image->width) * image->height * image->colors * 2u) {
        raw.dcraw_clear_mem(image);
        throwState(env, "real Xiaomi RAW probe: unexpected AHD byte count");
    }

    Sha256 ahd_hash;
    SampleStats ahd_stats;
    const auto *pixels = reinterpret_cast<const std::uint16_t *>(image->data);
    const std::size_t samples = static_cast<std::size_t>(image->width) * image->height * image->colors;
    for (std::size_t i = 0; i < samples; ++i) {
        const std::uint16_t v = pixels[i];
        ahd_hash.updateU16LE(v);
        ahd_stats.add(v, 0, 65535);
    }
    const std::string ahd_sha = ahd_hash.finishHex();

    std::ostringstream out;
    out << std::fixed << std::setprecision(6);
    out << "schema=m11camera.real_xiaomi_raw_probe.v1\n";
    out << "nativeAvailable=true\n";
    out << "librawVersion=" << runtime << "\n";
    out << "realXiaomiIdentityGate=true\n";
    out << "make=" << id.make << "\n";
    out << "model=" << id.model << "\n";
    out << "decoderName=" << decoder.decoder_name << "\n";
    out << "filters=0x" << std::hex << id.filters << std::dec << "\n";
    out << "rawSize=" << sizes.raw_width << "x" << sizes.raw_height << "\n";
    out << "visibleSize=" << sizes.width << "x" << sizes.height << "\n";
    out << "flip=" << sizes.flip << "\n";
    out << "preUnpackBlack=" << pre_black << "\n";
    out << "preUnpackMaximum=" << pre_maximum << "\n";
    out << "postUnpackBlack=" << post_black << "\n";
    out << "postUnpackMaximum=" << post_maximum << "\n";
    out << "unpackMs=" << elapsedMs(unpack_start, unpack_end) << "\n";
    out << "mosaicSamples=" << mosaic_stats.count << "\n";
    out << "mosaicSha256=" << mosaic_sha << "\n";
    out << "mosaicMin=" << mosaic_stats.minimum << "\n";
    out << "mosaicMax=" << mosaic_stats.maximum << "\n";
    out << "mosaicMean=" << (mosaic_stats.count ? static_cast<double>(mosaic_stats.sum) / mosaic_stats.count : 0.0) << "\n";
    out << "mosaicAtOrBelowBlack=" << mosaic_stats.at_or_below_black << "\n";
    out << "mosaicAtOrAboveMaximum=" << mosaic_stats.at_or_above_maximum << "\n";
    out << "rawpyOracleParamsApplied=true\n";
    out << "halfSize=false\n";
    out << "demosaic=AHD\n";
    out << "ahdMs=" << elapsedMs(ahd_start, ahd_end) << "\n";
    out << "ahdSize=" << image->width << "x" << image->height << "\n";
    out << "ahdColors=" << image->colors << "\n";
    out << "ahdBits=" << image->bits << "\n";
    out << "ahdSamples=" << ahd_stats.count << "\n";
    out << "ahdSha256=" << ahd_sha << "\n";
    out << "ahdMin=" << ahd_stats.minimum << "\n";
    out << "ahdMax=" << ahd_stats.maximum << "\n";
    out << "ahdMean=" << (ahd_stats.count ? static_cast<double>(ahd_stats.sum) / ahd_stats.count : 0.0) << "\n";
    out << "nativeRealXiaomiPixelDecodeCompleted=true\n";
    out << "realXiaomiPixelParityProven=false\n";
    out << "m11RendererInvoked=false\n";

    raw.dcraw_clear_mem(image);
    raw.recycle();
    return out.str();
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_m11_diagnostic_M11RealRawProbeBridge_nativeProbeRealXiaomiFd(
        JNIEnv *env, jclass /*clazz*/, jint fd) {
    try {
        const std::string result = runRealXiaomiProbe(env, static_cast<int>(fd));
        return env->NewStringUTF(result.c_str());
    } catch (const std::string &) {
        return nullptr;
    } catch (const std::exception &e) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, e.what());
        return nullptr;
    } catch (...) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, "real Xiaomi RAW probe: unknown native failure");
        return nullptr;
    }
}
