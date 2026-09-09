#include <libraw/libraw.h>

#include <cstdint>

// This is deliberately not a decoder yet.  It is an ABI/build probe proving
// that the exact LibRaw chosen for the Python RAW parity oracle can be linked
// into an Android arm64 shared object without importing any M11 rendering math.

extern "C" __attribute__((visibility("default")))
const char* m11_libraw_runtime_version() {
    return libraw_version();
}

extern "C" __attribute__((visibility("default")))
std::uint32_t m11_libraw_runtime_version_number() {
    return static_cast<std::uint32_t>(libraw_versionNumber());
}
