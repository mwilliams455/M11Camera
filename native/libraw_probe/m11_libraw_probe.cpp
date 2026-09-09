#include <libraw/libraw.h>

#include <cstdint>

#include "m11_fd_datastream.h"
#include "m11_raw_oracle_params.h"

// This is deliberately not a decoder yet. It is an ABI/build probe proving
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

extern "C" __attribute__((visibility("default")))
std::uint32_t m11_libraw_oracle_param_sentinel(int half_size) {
    LibRaw raw;
    auto &p = raw.imgdata.params;
    m11raw::applyRawpy0271OracleParams(p, half_size != 0);
    // Compact ABI smoke value, not a cryptographic fingerprint. Host CI checks
    // every parameter field individually against rawpy itself.
    return static_cast<std::uint32_t>(
            (p.user_qual & 0xff) |
            ((p.half_size & 0x1) << 8) |
            ((p.output_bps & 0xff) << 16) |
            ((p.no_auto_bright & 0x1) << 24));
}

extern "C" __attribute__((visibility("default")))
std::uint32_t m11_fd_datastream_abi_sentinel() {
    // Force the SAF/Posix fd datastream implementation through the Android
    // compiler/linker without opening or decoding any user file yet.
    m11raw::FdDatastream invalid(-1);
    return invalid.valid() == 0 ? 1u : 0u;
}
