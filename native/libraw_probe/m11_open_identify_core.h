#pragma once

#include <libraw/libraw.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#include "m11_fd_datastream.h"

namespace m11raw {

struct IdentifyResult {
    int open_code = LIBRAW_UNSPECIFIED_ERROR;
    std::string open_error;
    std::string libraw_version;
    std::string make;
    std::string model;
    std::string software;
    std::string normalized_make;
    std::string normalized_model;
    std::string decoder_name;
    unsigned decoder_flags = 0;
    unsigned raw_count = 0;
    unsigned colors = 0;
    unsigned filters = 0;
    unsigned raw_width = 0;
    unsigned raw_height = 0;
    unsigned width = 0;
    unsigned height = 0;
    unsigned left_margin = 0;
    unsigned top_margin = 0;
    int flip = 0;
    float iso_speed = 0.0f;
    unsigned black = 0;
    unsigned maximum = 0;
    std::array<unsigned, 4> cblack {{0, 0, 0, 0}};
    unsigned progress_flags = 0;
    bool decode_invoked = false;
};

inline std::string cleanField(const char *value) {
    if (value == nullptr) return std::string();
    std::string out(value);
    for (char &ch : out) {
        const unsigned char u = static_cast<unsigned char>(ch);
        if (ch == '\n' || ch == '\r' || ch == '\t' || std::iscntrl(u)) ch = ' ';
    }
    return out;
}

/**
 * Open and identify a RAW/DNG using the same seekable fd transport intended for
 * Android SAF. This function intentionally stops after LibRaw::open_datastream().
 * It must not unpack, demosaic, colour-convert, or render pixels.
 */
inline IdentifyResult identifyFdOnly(int source_fd) {
    IdentifyResult out;
    out.libraw_version = LibRaw::version();

    FdDatastream stream(source_fd);
    if (!stream.valid()) {
        out.open_code = LIBRAW_IO_ERROR;
        out.open_error = LibRaw::strerror(out.open_code);
        return out;
    }

    // stream is declared before raw so raw is destroyed/recycled first while
    // the external datastream remains alive.
    LibRaw raw;
    const int rc = raw.open_datastream(&stream);
    out.open_code = rc;
    out.open_error = LibRaw::strerror(rc);
    if (rc != LIBRAW_SUCCESS) {
        raw.recycle();
        return out;
    }

    const auto &id = raw.imgdata.idata;
    const auto &sizes = raw.imgdata.sizes;
    const auto &other = raw.imgdata.other;
    const auto &color = raw.imgdata.color;

    out.make = cleanField(id.make);
    out.model = cleanField(id.model);
    out.software = cleanField(id.software);
    out.normalized_make = cleanField(id.normalized_make);
    out.normalized_model = cleanField(id.normalized_model);
    out.raw_count = id.raw_count;
    out.colors = id.colors;
    out.filters = id.filters;
    out.raw_width = sizes.raw_width;
    out.raw_height = sizes.raw_height;
    out.width = sizes.width;
    out.height = sizes.height;
    out.left_margin = sizes.left_margin;
    out.top_margin = sizes.top_margin;
    out.flip = sizes.flip;
    out.iso_speed = other.iso_speed;
    out.black = color.black;
    out.maximum = color.maximum;
    for (int i = 0; i < 4; ++i) out.cblack[static_cast<size_t>(i)] = color.cblack[i];
    out.progress_flags = raw.imgdata.progress_flags;

    libraw_decoder_info_t decoder {};
    if (raw.get_decoder_info(&decoder) == LIBRAW_SUCCESS) {
        out.decoder_name = cleanField(decoder.decoder_name);
        out.decoder_flags = decoder.decoder_flags;
    }

    // This proof is intentionally identification-only. The flag is part of the
    // serialized evidence so the Android UI cannot accidentally imply otherwise.
    out.decode_invoked = false;
    raw.recycle();
    return out;
}

inline std::string serializeIdentifyEvidence(const IdentifyResult &r) {
    std::ostringstream s;
    s << "schema=m11camera.libraw_identify.v1\n";
    s << "librawVersion=" << r.libraw_version << '\n';
    s << "openCode=" << r.open_code << '\n';
    s << "openError=" << r.open_error << '\n';
    s << "make=" << r.make << '\n';
    s << "model=" << r.model << '\n';
    s << "software=" << r.software << '\n';
    s << "normalizedMake=" << r.normalized_make << '\n';
    s << "normalizedModel=" << r.normalized_model << '\n';
    s << "decoderName=" << r.decoder_name << '\n';
    s << "decoderFlags=" << r.decoder_flags << '\n';
    s << "rawCount=" << r.raw_count << '\n';
    s << "colors=" << r.colors << '\n';
    s << "filters=0x" << std::hex << std::setw(8) << std::setfill('0') << r.filters << std::dec << '\n';
    s << "rawSize=" << r.raw_width << 'x' << r.raw_height << '\n';
    s << "visibleSize=" << r.width << 'x' << r.height << '\n';
    s << "leftMargin=" << r.left_margin << '\n';
    s << "topMargin=" << r.top_margin << '\n';
    s << "flip=" << r.flip << '\n';
    s << std::fixed << std::setprecision(6);
    s << "isoSpeed=" << r.iso_speed << '\n';
    s << "black=" << r.black << '\n';
    s << "maximum=" << r.maximum << '\n';
    s << "cblack=" << r.cblack[0] << ',' << r.cblack[1] << ',' << r.cblack[2] << ',' << r.cblack[3] << '\n';
    s << "progressFlags=" << r.progress_flags << '\n';
    s << "decodeInvoked=" << (r.decode_invoked ? "true" : "false") << '\n';
    return s.str();
}

} // namespace m11raw
