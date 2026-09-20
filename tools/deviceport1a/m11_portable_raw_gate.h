#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>

namespace m11raw {
// Input capability descriptor, deliberately without make/model/camera-ID fields.
struct PortableRawDescriptor {
    unsigned dngVersion, rawCount, colors, filters;
    unsigned rawWidth, rawHeight, width, height, left, top, maximum;
    std::string colorDescription;
};
inline std::string portableBayerPhase(unsigned filters, const std::string& desc) {
    if (filters <= 1000) throw std::invalid_argument("DEVICEPORT1A: only conventional RGB Bayer DNG is supported");
    std::string phase;
    for (unsigned y=0; y<8; ++y) for (unsigned x=0; x<2; ++x) {
        const unsigned plane = (filters >> ((((y << 1) & 14u) + x) << 1)) & 3u;
        if (plane >= desc.size()) throw std::invalid_argument("DEVICEPORT1A: invalid CFA color index");
        const char c = desc[plane];
        if (y < 2) phase += c;
        else if (c != phase[(y % 2)*2+x]) throw std::invalid_argument("DEVICEPORT1A: non-2x2 CFA is unsupported");
    }
    if (phase!="RGGB" && phase!="GRBG" && phase!="GBRG" && phase!="BGGR")
        throw std::invalid_argument("DEVICEPORT1A: unsupported CFA color layout");
    return phase;
}
inline std::string validatePortableRaw(const PortableRawDescriptor& d) {
    if (!d.dngVersion || d.rawCount!=1 || d.colors!=3)
        throw std::invalid_argument("DEVICEPORT1A: requires a single-image, three-color Bayer DNG");
    if (!d.rawWidth || !d.rawHeight || !d.width || !d.height ||
        static_cast<std::uint64_t>(d.left)+d.width > d.rawWidth ||
        static_cast<std::uint64_t>(d.top)+d.height > d.rawHeight)
        throw std::invalid_argument("DEVICEPORT1A: invalid RAW/active-area dimensions");
    // Bounds prevent overflow in the 16-bit RGB output interface, not a phone-size whitelist.
    if (static_cast<std::uint64_t>(d.rawWidth)*d.rawHeight > 0x7fffffffu/8u)
        throw std::invalid_argument("DEVICEPORT1A: RAW exceeds safe buffer limits");
    if (!d.maximum || d.maximum>65535)
        throw std::invalid_argument("DEVICEPORT1A: unsupported integer RAW white level");
    return portableBayerPhase(d.filters, d.colorDescription);
}
} // namespace m11raw
