package com.m11.diagnostic;

/**
 * JNI entry point used only for the bundled non-photographic 32x32 RAW fixture.
 * The native side independently refuses any file that does not match the exact
 * synthetic metadata/decoder gate before unpack/AHD is allowed.
 */
public final class M11RawSelfTestBridge {
    private M11RawSelfTestBridge() {}

    public static byte[] runSyntheticFixture(int fd) {
        if (!M11NativeRawBridge.isAvailable()) {
            throw new IllegalStateException("native LibRaw bridge unavailable: " + M11NativeRawBridge.loadError());
        }
        if (fd < 0) throw new IllegalArgumentException("invalid fixture fd");
        byte[] packet = nativeRunSyntheticFixture(fd);
        if (packet == null) throw new IllegalStateException("native synthetic RAW self-test returned null");
        return packet;
    }

    private static native byte[] nativeRunSyntheticFixture(int fd);
}
