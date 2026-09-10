package com.m11.diagnostic;

/**
 * Separate JNI boundary for the explicitly promoted real-Xiaomi RAW diagnostics.
 *
 * This bridge is not used by the existing identify-only DNG path. Native code
 * must pass the narrow Xiaomi metadata/decoder gate before unpack/AHD is allowed.
 * REALRAW1C may additionally export only the resulting AHD bitmap to a caller-
 * selected fd for private parity analysis. The M11 renderer remains disconnected.
 */
public final class M11RealRawProbeBridge {
    private M11RealRawProbeBridge() {}

    public static String probeRealXiaomiFd(int fd) {
        requireNative();
        if (fd < 0) throw new IllegalArgumentException("invalid Xiaomi DNG fd");
        String result = nativeProbeRealXiaomiFd(fd);
        if (result == null) throw new IllegalStateException("native real Xiaomi RAW probe returned null");
        return result;
    }

    public static String exportRealXiaomiAhdFd(int sourceFd, int outputFd) {
        requireNative();
        if (sourceFd < 0) throw new IllegalArgumentException("invalid Xiaomi DNG fd");
        if (outputFd < 0) throw new IllegalArgumentException("invalid AHD export fd");
        String result = nativeExportRealXiaomiAhdFd(sourceFd, outputFd);
        if (result == null) throw new IllegalStateException("native REALRAW1C AHD exporter returned null");
        return result;
    }

    private static void requireNative() {
        if (!M11NativeRawBridge.isAvailable()) {
            throw new IllegalStateException(
                    "native LibRaw bridge unavailable: " + M11NativeRawBridge.loadError());
        }
    }

    private static native String nativeProbeRealXiaomiFd(int fd);
    private static native String nativeExportRealXiaomiAhdFd(int sourceFd, int outputFd);
}
