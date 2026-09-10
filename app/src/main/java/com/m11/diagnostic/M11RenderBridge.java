package com.m11.diagnostic;

import android.graphics.Bitmap;

/**
 * RENDER1A bridge for a controlled, offline Xiaomi-DNG -> M11 Standard render.
 *
 * This class deliberately does not load firmware assets itself.  Callers must
 * first pass the canonical binary through {@link M11ReferenceAssetLoader}; the
 * loader is the single provenance/hash gate for firmware-derived tables.
 * Likewise, callers must derive cameraToM11Reference from DNG metadata through
 * M11SourceAdapterCore + M11ReferenceBasisCore.
 *
 * The native side reuses the narrow REALRAW1C Xiaomi/LibRaw decoder gate, uses
 * the frozen rawpy 0.27.1/LibRaw 0.22.1 AHD parameters, renders directly into
 * an Android RGBA_8888 Bitmap, and never applies the unresolved third SRO.
 */
public final class M11RenderBridge {
    static {
        System.loadLibrary("m11rawjni");
    }

    private M11RenderBridge() {}

    public static final class Result {
        public final Bitmap bitmap;
        public final String diagnostics;

        Result(Bitmap bitmap, String diagnostics) {
            this.bitmap = bitmap;
            this.diagnostics = diagnostics;
        }
    }

    public static Result renderStandardFd(
            int fd,
            double[] cameraToM11Reference,
            M11ReferenceRendererCore.Tables tables) {
        if (fd < 0) throw new IllegalArgumentException("fd must be valid");
        if (cameraToM11Reference == null || cameraToM11Reference.length != 9) {
            throw new IllegalArgumentException("cameraToM11Reference must be 3x3 row-major");
        }
        if (tables == null) throw new IllegalArgumentException("tables == null");
        requireLength(tables.cc0, 9, "CC0");
        requireLength(tables.cc1, 9, "CC1");
        requireLength(tables.toneX, 1024, "toneX");
        if (tables.toneCurves == null || tables.toneCurves.length != 7) {
            throw new IllegalArgumentException("toneCurves must contain seven firmware states");
        }
        double[] toneFlat = new double[7 * 1024];
        for (int state = 0; state < 7; state++) {
            requireLength(tables.toneCurves[state], 1024, "toneCurve[" + state + "]");
            System.arraycopy(tables.toneCurves[state], 0, toneFlat, state * 1024, 1024);
        }
        requireLength(tables.gammaX, 4096, "gammaX");
        requireLength(tables.gammaY, 4096, "gammaY");

        Object[] nativeResult = nativeRenderRealXiaomiStandardFd(
                fd,
                cameraToM11Reference.clone(),
                tables.cc0.clone(),
                tables.cc1.clone(),
                tables.toneX.clone(),
                toneFlat,
                tables.gammaX.clone(),
                tables.gammaY.clone());
        if (nativeResult == null || nativeResult.length != 2 ||
                !(nativeResult[0] instanceof Bitmap) || !(nativeResult[1] instanceof String)) {
            throw new IllegalStateException("RENDER1A native result contract mismatch");
        }
        return new Result((Bitmap) nativeResult[0], (String) nativeResult[1]);
    }

    private static void requireLength(double[] values, int expected, String name) {
        if (values == null || values.length != expected) {
            throw new IllegalArgumentException(name + " must contain exactly " + expected + " values");
        }
    }

    private static native Object[] nativeRenderRealXiaomiStandardFd(
            int fd,
            double[] cameraToM11Reference,
            double[] cc0,
            double[] cc1,
            double[] toneX,
            double[] toneCurvesFlat,
            double[] gammaX,
            double[] gammaY);
}
