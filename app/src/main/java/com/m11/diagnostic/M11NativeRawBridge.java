package com.m11.diagnostic;

/**
 * Narrow JNI boundary for LibRaw identification.
 *
 * APK1A deliberately exposes only open/identify. Pixel unpack, demosaic and
 * rendering remain disabled until same-byte DNG parity is proven.
 */
public final class M11NativeRawBridge {
    private static final boolean LOADED;
    private static final String LOAD_ERROR;

    static {
        boolean loaded = false;
        String error = "";
        try {
            System.loadLibrary("m11rawjni");
            loaded = true;
        } catch (Throwable t) {
            error = t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage());
        }
        LOADED = loaded;
        LOAD_ERROR = error;
    }

    private M11NativeRawBridge() {}

    public static boolean isAvailable() {
        return LOADED;
    }

    public static String loadError() {
        return LOAD_ERROR;
    }

    public static String identifyFd(int fd) {
        if (!LOADED) {
            return "schema=m11camera.libraw_identify.v1\n" +
                    "nativeAvailable=false\n" +
                    "loadError=" + LOAD_ERROR + "\n" +
                    "decodeInvoked=false\n";
        }
        if (fd < 0) {
            return "schema=m11camera.libraw_identify.v1\n" +
                    "nativeAvailable=true\n" +
                    "openCode=invalid-fd\n" +
                    "decodeInvoked=false\n";
        }
        return nativeIdentifyFd(fd);
    }

    private static native String nativeIdentifyFd(int fd);
}
