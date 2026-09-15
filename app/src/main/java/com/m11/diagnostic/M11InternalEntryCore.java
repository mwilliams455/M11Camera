package com.m11.diagnostic;

/**
 * Research-only helpers for the firmware-closed XYZ-D50 -> Leica internal-space entry.
 *
 * Firmware evidence closes PCS_TO_INTERNAL as the fixed D50 PCS -> Leica working-space
 * transform.  This class deliberately does not alter the normal RENDER1H workflow;
 * it exists for the isolated old-entry vs direct-K device A/B.
 */
public final class M11InternalEntryCore {
    private M11InternalEntryCore() {}

    public static final double[] PCS_TO_INTERNAL = {
            1.3460, -0.2556, -0.0511,
            -0.5446, 1.5082, 0.0205,
            0.0000, 0.0000, 1.2123
    };

    public static final double[] IDENTITY_CC0 = {
            1.0, 0.0, 0.0,
            0.0, 1.0, 0.0,
            0.0, 0.0, 1.0
    };

    public static final class Comparison {
        public final double[] oldEffectiveCameraToInternal;
        public final double[] directCameraToInternal;
        public final double bestScalarOldToDirect;
        public final double directRelativeEv;
        public final double maxAbsResidualAfterScalar;
        public final double rmsResidualAfterScalar;

        Comparison(double[] oldEffectiveCameraToInternal,
                   double[] directCameraToInternal,
                   double bestScalarOldToDirect,
                   double directRelativeEv,
                   double maxAbsResidualAfterScalar,
                   double rmsResidualAfterScalar) {
            this.oldEffectiveCameraToInternal = oldEffectiveCameraToInternal.clone();
            this.directCameraToInternal = directCameraToInternal.clone();
            this.bestScalarOldToDirect = bestScalarOldToDirect;
            this.directRelativeEv = directRelativeEv;
            this.maxAbsResidualAfterScalar = maxAbsResidualAfterScalar;
            this.rmsResidualAfterScalar = rmsResidualAfterScalar;
        }
    }

    /** Camera RGB -> Leica internal, assuming cameraToXyzD50 already includes source WB. */
    public static double[] cameraToInternal(double[] cameraToXyzD50) {
        return multiply3x3(PCS_TO_INTERNAL, cameraToXyzD50);
    }

    /**
     * Clone the selected firmware tables while replacing only CC0 with identity.
     * This is mathematically equivalent to useCc0=false because the native CC0 stage
     * is a pure 3x3 multiply, while allowing the exact same JNI/native renderer entry
     * point to be reused without modifying the frozen RENDER1H native path.
     */
    public static M11ReferenceRendererCore.Tables withIdentityCc0(M11ReferenceRendererCore.Tables source) {
        if (source == null) throw new IllegalArgumentException("source tables == null");
        return new M11ReferenceRendererCore.Tables(
                IDENTITY_CC0,
                source.cc1,
                source.toneX,
                source.toneCurves,
                source.gammaX,
                source.gammaY);
    }

    /** Compare effective old entry (static CC0 * old pre-CC0 bridge) with direct K entry. */
    public static Comparison compareEffectiveEntries(
            double[] cameraToXyzD50,
            double[] oldCameraToM11Reference,
            double[] selectedStaticCc0) {
        requireMatrix(cameraToXyzD50, "cameraToXyzD50");
        requireMatrix(oldCameraToM11Reference, "oldCameraToM11Reference");
        requireMatrix(selectedStaticCc0, "selectedStaticCc0");

        double[] oldEffective = multiply3x3(selectedStaticCc0, oldCameraToM11Reference);
        double[] direct = cameraToInternal(cameraToXyzD50);
        double dotOldDirect = 0.0;
        double dotDirectDirect = 0.0;
        for (int i = 0; i < 9; i++) {
            dotOldDirect += oldEffective[i] * direct[i];
            dotDirectDirect += direct[i] * direct[i];
        }
        if (!(dotDirectDirect > 0.0)) throw new IllegalArgumentException("direct entry has zero norm");
        double scalar = dotOldDirect / dotDirectDirect;
        if (!(scalar > 0.0) || !Double.isFinite(scalar)) {
            throw new IllegalArgumentException("invalid old/direct scalar");
        }
        double maxAbs = 0.0;
        double sumSq = 0.0;
        for (int i = 0; i < 9; i++) {
            double residual = oldEffective[i] - scalar * direct[i];
            maxAbs = Math.max(maxAbs, Math.abs(residual));
            sumSq += residual * residual;
        }
        return new Comparison(
                oldEffective,
                direct,
                scalar,
                -Math.log(scalar) / Math.log(2.0),
                maxAbs,
                Math.sqrt(sumSq / 9.0));
    }

    public static double[] multiply3x3(double[] a, double[] b) {
        requireMatrix(a, "left matrix");
        requireMatrix(b, "right matrix");
        double[] out = new double[9];
        for (int r = 0; r < 3; r++) {
            for (int c = 0; c < 3; c++) {
                out[r * 3 + c] =
                        a[r * 3] * b[c] +
                        a[r * 3 + 1] * b[3 + c] +
                        a[r * 3 + 2] * b[6 + c];
            }
        }
        return out;
    }

    private static void requireMatrix(double[] matrix, String name) {
        if (matrix == null || matrix.length != 9) {
            throw new IllegalArgumentException(name + " must be 3x3 row-major");
        }
        for (double value : matrix) {
            if (!Double.isFinite(value)) throw new IllegalArgumentException(name + " contains non-finite value");
        }
    }
}
