package com.m11.diagnostic;

/**
 * Separate JNI boundary for the explicitly promoted real-Xiaomi RAW probe.
 *
 * This bridge is not used by the existing identify-only DNG path. Native code
 * must pass the narrow Xiaomi metadata/decoder gate before unpack/AHD is allowed.
 * The M11 renderer remains disconnected.
 */
public final class M11RealRawProbeBridge {
    private M11RealRawProbeBridge() {}

    public static String probeRealXiaomiFd(int fd) {
        if (!M11NativeRawBridge.isAvailable()) {
            throw new IllegalStateException(
                    "native LibRaw bridge unavailable: " + M11NativeRawBridge.loadError());
        }
        if (fd < 0) throw new IllegalArgumentException("invalid Xiaomi DNG fd");
        String result = nativeProbeRealXiaomiFd(fd);
        if (result == null) throw new IllegalStateException("native real Xiaomi RAW probe returned null");
        return result;
    }

    private static native String nativeProbeRealXiaomiFd(int fd);
}
