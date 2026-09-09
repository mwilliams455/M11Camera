package com.m11.diagnostic;

import java.util.Arrays;

/**
 * Firmware-evidence constants that are safe to carry into APK1A.
 *
 * This class deliberately does NOT decide where the third SRO matrix belongs in
 * the M11 render graph.  Placement remains an explicit research variable until
 * the firmware consumer path is closed.
 */
public final class M11MatrixCore {
    private M11MatrixCore() {}

    public static final int Q9_SCALE = 512;

    /** Identity SRO record in Leica Q9 storage. */
    public static final int[] SRO_IDENTITY_Q9 = {
            512, 0, 0,
            0, 512, 0,
            0, 0, 512
    };

    /** D65/CM2 SRO record recovered from M11 firmware. */
    public static final int[] SRO_CM2_Q9 = {
            916, -350, -54,
            -151, 719, -56,
            14, -184, 682
    };

    /**
     * Current third M11 SRO target.  This is the corrected target; do not replace
     * it with the stale earlier [212,-207,-5,-620,1576,68,43,335,686] record.
     */
    public static final int[] SRO_THIRD_Q9 = {
            212, -165, -71,
            -73, 676, 85,
            -27, 174, 285
    };

    public enum MatrixPlacement {
        DISABLED,
        PRE_WORKING_SPACE,
        POST_WORKING_SPACE,
        PRE_TONE
    }

    /** Leica Q9 quantizer: scale by 512, round half away from zero, saturate int32. */
    public static int quantizeQ9(double x) {
        double u = x * Q9_SCALE;
        double rounded = u >= 0.0 ? Math.floor(u + 0.5) : Math.ceil(u - 0.5);
        if (rounded > Integer.MAX_VALUE) return Integer.MAX_VALUE;
        if (rounded < Integer.MIN_VALUE) return Integer.MIN_VALUE;
        return (int) rounded;
    }

    public static double dequantizeQ9(int q9) {
        return q9 / (double) Q9_SCALE;
    }

    public static double[] dequantizeMatrix(int[] q9) {
        requireMatrix(q9);
        double[] out = new double[9];
        for (int i = 0; i < 9; i++) out[i] = dequantizeQ9(q9[i]);
        return out;
    }

    /** Applies a row-major Q9 3x3 matrix to one RGB triplet without output clipping. */
    public static double[] applyQ9(int[] q9, double r, double g, double b) {
        requireMatrix(q9);
        return new double[] {
                (q9[0] * r + q9[1] * g + q9[2] * b) / Q9_SCALE,
                (q9[3] * r + q9[4] * g + q9[5] * b) / Q9_SCALE,
                (q9[6] * r + q9[7] * g + q9[8] * b) / Q9_SCALE
        };
    }

    public static String thirdTargetSummary() {
        return "third-SRO-Q9=" + Arrays.toString(SRO_THIRD_Q9);
    }

    private static void requireMatrix(int[] q9) {
        if (q9 == null || q9.length != 9) {
            throw new IllegalArgumentException("Q9 matrix must contain exactly 9 coefficients");
        }
    }
}
