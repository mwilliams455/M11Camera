#include <jni.h>

#include <libraw/libraw.h>
#include <zlib.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

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

double elapsedMs(std::chrono::steady_clock::time_point start,
                 std::chrono::steady_clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::string runExport(JNIEnv *env, int source_fd, int output_fd) {
    if (output_fd < 0) throwState(env, "REALRAW1C export: invalid output fd");

    m11raw::FdDatastream stream(source_fd);
    if (!stream.valid()) throwState(env, "REALRAW1C export: invalid source fd");

    LibRaw raw;
    int rc = raw.open_datastream(&stream);
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "REALRAW1C export: open_datastream failed: " + std::string(LibRaw::strerror(rc)));

    const std::string runtime = LibRaw::version();
    if (runtime.rfind("0.22.1", 0) != 0)
        throwState(env, "REALRAW1C export: LibRaw version gate failed: " + runtime);

    const auto &id = raw.imgdata.idata;
    const auto &sizes = raw.imgdata.sizes;
    const auto &color = raw.imgdata.color;
    libraw_decoder_info_t decoder {};
    if (raw.get_decoder_info(&decoder) != LIBRAW_SUCCESS)
        throwState(env, "REALRAW1C export: decoder identity unavailable");

    // EXACTLY THE SAME NARROW REAL-XIAOMI PROMOTION GATE AS REALRAW1B.
    // The original identify-only JNI remains a different translation unit and
    // never calls unpack/process. This exporter never invokes the M11 renderer.
    if (!equalsField(id.make, kMake) || !equalsField(id.model, kModel) ||
        id.raw_count != 1 || id.colors != 3 || id.filters != kFilters ||
        sizes.raw_width != kWidth || sizes.raw_height != kHeight ||
        sizes.width != kWidth || sizes.height != kHeight ||
        sizes.left_margin != 0 || sizes.top_margin != 0 ||
        color.maximum != kMaximum ||
        decoder.decoder_name == nullptr || std::strcmp(decoder.decoder_name, kDecoder) != 0) {
        throwState(env, "REALRAW1C export: metadata/decoder gate failed; refusing pixel decode/export");
    }

    const auto unpack_start = std::chrono::steady_clock::now();
    rc = raw.unpack();
    const auto unpack_end = std::chrono::steady_clock::now();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "REALRAW1C export: unpack failed: " + std::string(LibRaw::strerror(rc)));

    // Frozen rawpy 0.27.1 / LibRaw 0.22.1 contract; 4096 long edge => full AHD.
    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);
    const auto ahd_start = std::chrono::steady_clock::now();
    rc = raw.dcraw_process();
    if (rc != LIBRAW_SUCCESS)
        throwState(env, "REALRAW1C export: AHD process failed: " + std::string(LibRaw::strerror(rc)));

    int mem_error = LIBRAW_SUCCESS;
    libraw_processed_image_t *image = raw.dcraw_make_mem_image(&mem_error);
    const auto ahd_end = std::chrono::steady_clock::now();
    if (image == nullptr || mem_error != LIBRAW_SUCCESS)
        throwState(env, "REALRAW1C export: memory image failed");

    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3) {
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: unexpected AHD output type");
    }
    const std::size_t expected_bytes =
        static_cast<std::size_t>(image->width) * image->height * image->colors * 2u;
    if (image->data_size != expected_bytes) {
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: unexpected AHD byte count");
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "REALRAW1C AHD export is defined as little-endian u16 and requires a little-endian Android target"
#endif

    const auto gzip_start = std::chrono::steady_clock::now();
    const int gzip_fd = dup(output_fd);
    if (gzip_fd < 0) {
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: dup(output fd) failed");
    }

    gzFile gz = gzdopen(gzip_fd, "wb1");
    if (gz == nullptr) {
        close(gzip_fd);
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: gzdopen failed");
    }
    gzbuffer(gz, 1024 * 1024);

    const int written = gzwrite(gz, image->data, static_cast<unsigned int>(image->data_size));
    if (written != static_cast<int>(image->data_size)) {
        int zerr = Z_OK;
        const char *zmsg = gzerror(gz, &zerr);
        std::string detail = zmsg != nullptr ? zmsg : "unknown gzip error";
        gzclose(gz);
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: gzwrite failed: " + detail);
    }
    const int close_rc = gzclose(gz); // closes only the dup; Java still owns output_fd.
    if (close_rc != Z_OK) {
        raw.dcraw_clear_mem(image);
        throwState(env, "REALRAW1C export: gzclose failed");
    }
    fsync(output_fd);
    const auto gzip_end = std::chrono::steady_clock::now();

    long long compressed_bytes = -1;
    struct stat st {};
    if (fstat(output_fd, &st) == 0 && S_ISREG(st.st_mode))
        compressed_bytes = static_cast<long long>(st.st_size);

    const uLong uncompressed_crc = crc32(
        crc32(0L, Z_NULL, 0),
        reinterpret_cast<const Bytef *>(image->data),
        static_cast<uInt>(image->data_size));

    std::ostringstream out;
    out << "schema=m11camera.real_xiaomi_ahd_export.v1\n";
    out << "realXiaomiIdentityGate=true\n";
    out << "librawVersion=" << runtime << "\n";
    out << "make=" << id.make << "\n";
    out << "model=" << id.model << "\n";
    out << "decoderName=" << decoder.decoder_name << "\n";
    out << "rawpyOracleParamsApplied=true\n";
    out << "halfSize=false\n";
    out << "demosaic=AHD\n";
    out << "ahdWidth=" << image->width << "\n";
    out << "ahdHeight=" << image->height << "\n";
    out << "ahdColors=" << image->colors << "\n";
    out << "ahdBits=" << image->bits << "\n";
    out << "ahdUncompressedBytes=" << image->data_size << "\n";
    out << "ahdCrc32=" << std::hex << static_cast<unsigned long>(uncompressed_crc) << std::dec << "\n";
    out << "gzipCompressedBytes=" << compressed_bytes << "\n";
    out << "unpackMs=" << elapsedMs(unpack_start, unpack_end) << "\n";
    out << "ahdMs=" << elapsedMs(ahd_start, ahd_end) << "\n";
    out << "gzipMs=" << elapsedMs(gzip_start, gzip_end) << "\n";
    out << "exportFormat=gzip(raw interleaved RGB uint16 little-endian)\n";
    out << "nativeRealXiaomiAhdExportCompleted=true\n";
    out << "m11RendererInvoked=false\n";

    raw.dcraw_clear_mem(image);
    raw.recycle();
    return out.str();
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_m11_diagnostic_M11RealRawProbeBridge_nativeExportRealXiaomiAhdFd(
        JNIEnv *env, jclass /*clazz*/, jint source_fd, jint output_fd) {
    try {
        const std::string result = runExport(env, static_cast<int>(source_fd), static_cast<int>(output_fd));
        return env->NewStringUTF(result.c_str());
    } catch (const std::string &) {
        return nullptr;
    } catch (const std::exception &e) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, e.what());
        return nullptr;
    } catch (...) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls != nullptr) env->ThrowNew(cls, "REALRAW1C export: unknown native failure");
        return nullptr;
    }
}
