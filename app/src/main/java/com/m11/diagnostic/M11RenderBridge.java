package com.m11.diagnostic;

import android.graphics.Bitmap;

/**
 * Native bridge for the validated M11 Standard renderer plus isolated research
 * candidates. Firmware assets remain provenance-gated by the caller.
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
        double[] toneFlat = validateAndFlatten(cameraToM11Reference, tables);
        Object[] nativeResult = nativeRenderRealXiaomiStandardFd(
                fd,
                cameraToM11Reference.clone(),
                tables.cc0.clone(),
                tables.cc1.clone(),
                tables.toneX.clone(),
                toneFlat,
                tables.gammaX.clone(),
                tables.gammaY.clone());
        return decodeResult(nativeResult, "RENDER1H");
    }

    public static Result renderStandardB2rWbPlacementFd(
            int fd,
            double[] cameraToM11Reference,
            double[] asShotNeutral,
            M11ReferenceRendererCore.Tables tables) {
        double[] toneFlat = validateAndFlatten(cameraToM11Reference, tables);
        requireLength(asShotNeutral, 3, "AsShotNeutral");
        for (double value : asShotNeutral) {
            if (!Double.isFinite(value) || value <= 0.0) {
                throw new IllegalArgumentException("AsShotNeutral must be finite and positive");
            }
        }
        Object[] nativeResult = nativeRenderRealXiaomiStandardB2rWbPlacementFd(
                fd,
                cameraToM11Reference.clone(),
                asShotNeutral.clone(),
                tables.cc0.clone(),
                tables.cc1.clone(),
                tables.toneX.clone(),
                toneFlat,
                tables.gammaX.clone(),
                tables.gammaY.clone());
        return decodeResult(nativeResult, "B2RWBPLACE1A");
    }

    private static double[] validateAndFlatten(
            double[] cameraToM11Reference,
            M11ReferenceRendererCore.Tables tables) {
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
        return toneFlat;
    }

    private static Result decodeResult(Object[] nativeResult, String label) {
        if (nativeResult == null || nativeResult.length != 2 ||
                !(nativeResult[0] instanceof Bitmap) || !(nativeResult[1] instanceof String)) {
            throw new IllegalStateException(label + " native result contract mismatch");
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

    private static native Object[] nativeRenderRealXiaomiStandardB2rWbPlacementFd(
            int fd,
            double[] cameraToM11Reference,
            double[] asShotNeutral,
            double[] cc0,
            double[] cc1,
            double[] toneX,
            double[] toneCurvesFlat,
            double[] gammaX,
            double[] gammaY);
}
