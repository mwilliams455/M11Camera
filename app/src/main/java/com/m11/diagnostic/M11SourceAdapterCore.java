package com.m11.diagnostic;

/**
 * Target-agnostic Xiaomi/DNG dual-illuminant source calibration.
 *
 * Numerical port of renderer/source_adapter/dng_dual_illuminant.py. This class
 * ends at linear scene-referred XYZ D50; no Leica target rendering belongs here.
 */
public final class M11SourceAdapterCore {
    private M11SourceAdapterCore() {}

    public static final double[] D50_XYZ = {0.9642, 1.0, 0.8249};

    public static final class Result {
        public final double[] cameraToXyzD50;
        public final double interpolationFactor;
        public final double[] referenceNeutral;

        Result(double[] cameraToXyzD50, double interpolationFactor, double[] referenceNeutral) {
            this.cameraToXyzD50 = cameraToXyzD50;
            this.interpolationFactor = interpolationFactor;
            this.referenceNeutral = referenceNeutral;
        }
    }

    public static Result buildDualIlluminantTransform(
            int referenceIlluminant1,
            int referenceIlluminant2,
            double[] calibrationTransform1,
            double[] calibrationTransform2,
            double[] colorMatrix1,
            double[] colorMatrix2,
            double[] forwardMatrix1,
            double[] forwardMatrix2,
            double[] neutralColorPoint) {
        double factor = findDngInterpolationFactor(
                referenceIlluminant1, referenceIlluminant2,
                calibrationTransform1, calibrationTransform2,
                colorMatrix1, colorMatrix2, neutralColorPoint);
        double[] nfm1 = normalizeForwardMatrix(forwardMatrix1);
        double[] nfm2 = normalizeForwardMatrix(forwardMatrix2);
        return calculateCameraToXyzD50Transform(
                nfm1, nfm2, calibrationTransform1, calibrationTransform2,
                neutralColorPoint, factor);
    }

    /** ColorMatrix inputs are XYZ->reference-camera and are deliberately NOT normalized. */
    public static double findDngInterpolationFactor(
            int referenceIlluminant1,
            int referenceIlluminant2,
            double[] calibrationTransform1,
            double[] calibrationTransform2,
            double[] colorMatrix1,
            double[] colorMatrix2,
            double[] neutralColorPoint) {
        double temperature1 = illuminantKelvin(referenceIlluminant1);
        double temperature2 = illuminantKelvin(referenceIlluminant2);
        requireMatrix(calibrationTransform1, "calibrationTransform1");
        requireMatrix(calibrationTransform2, "calibrationTransform2");
        requireMatrix(colorMatrix1, "colorMatrix1");
        requireMatrix(colorMatrix2, "colorMatrix2");
        requireVector(neutralColorPoint, "neutralColorPoint");

        double[] xyzToCamera1 = multiply3x3(calibrationTransform1, colorMatrix1);
        double[] xyzToCamera2 = multiply3x3(calibrationTransform2, colorMatrix2);
        double lower = Math.min(temperature1, temperature2);
        double upper = Math.max(temperature1, temperature2);
        double factor = 0.5;
        double oldFactor = factor;

        for (int iteration = 0; iteration < 30; iteration++) {
            double[] xyzToCamera = lerp(xyzToCamera1, xyzToCamera2, factor);
            double[] cameraToXyz = inverse3(xyzToCamera);
            double[] neutralXyz = multiply3x1(cameraToXyz, neutralColorPoint);
            double[] xy = cieXyFromXyz(neutralXyz);
            double temperature = mccamyCct(xy[0], xy[1]);

            double newFactor;
            if (temperature <= lower) {
                newFactor = 1.0;
            } else if (temperature >= upper) {
                newFactor = 0.0;
            } else {
                double invT = 1.0 / temperature;
                newFactor = (invT - 1.0 / upper) / (1.0 / lower - 1.0 / upper);
            }
            if (lower == temperature1) newFactor = 1.0 - newFactor;

            // Preserve the inspected Photon damping exactly.
            factor = 0.5 * (newFactor + oldFactor);
            double diff = Math.abs(oldFactor - factor);
            oldFactor = factor;
            if (diff <= 1e-4) break;
        }
        return factor;
    }

    public static double[] normalizeForwardMatrix(double[] forwardMatrix) {
        requireMatrix(forwardMatrix, "forwardMatrix");
        double[] xyz = multiply3x1(forwardMatrix, new double[] {1.0, 1.0, 1.0});
        for (double v : xyz) {
            if (!Double.isFinite(v) || Math.abs(v) < 1e-12) {
                throw new IllegalArgumentException("forwardMatrix cannot be normalized");
            }
        }
        double[] out = forwardMatrix.clone();
        for (int row = 0; row < 3; row++) {
            double scale = D50_XYZ[row] / xyz[row];
            for (int col = 0; col < 3; col++) out[row * 3 + col] *= scale;
        }
        return out;
    }

    public static Result calculateCameraToXyzD50Transform(
            double[] normalizedForwardMatrix1,
            double[] normalizedForwardMatrix2,
            double[] calibrationTransform1,
            double[] calibrationTransform2,
            double[] neutralColorPoint,
            double interpolationFactor) {
        requireMatrix(normalizedForwardMatrix1, "normalizedForwardMatrix1");
        requireMatrix(normalizedForwardMatrix2, "normalizedForwardMatrix2");
        requireMatrix(calibrationTransform1, "calibrationTransform1");
        requireMatrix(calibrationTransform2, "calibrationTransform2");
        requireVector(neutralColorPoint, "neutralColorPoint");

        double[] interpolatedCal = lerp(calibrationTransform1, calibrationTransform2, interpolationFactor);
        double[] inverseCal = inverse3(interpolatedCal);
        double[] referenceNeutral = multiply3x1(inverseCal, neutralColorPoint);
        double maxNeutral = -Double.MAX_VALUE;
        for (int i = 0; i < 3; i++) {
            referenceNeutral[i] = Math.max(referenceNeutral[i], 1e-6);
            maxNeutral = Math.max(maxNeutral, referenceNeutral[i]);
        }
        double[] whiteBalance = {
                maxNeutral / referenceNeutral[0], 0, 0,
                0, maxNeutral / referenceNeutral[1], 0,
                0, 0, maxNeutral / referenceNeutral[2]
        };
        double[] interpolatedFm = lerp(normalizedForwardMatrix1, normalizedForwardMatrix2, interpolationFactor);
        double[] cameraToXyz = multiply3x3(multiply3x3(interpolatedFm, whiteBalance), inverseCal);
        return new Result(cameraToXyz, interpolationFactor, referenceNeutral);
    }

    public static double[] applyCameraToXyz(double[] cameraRgb, double[] transform) {
        requireVector(cameraRgb, "cameraRgb");
        requireMatrix(transform, "transform");
        return multiply3x1(transform, cameraRgb);
    }

    static double[] cieXyFromXyz(double[] xyz) {
        requireVector(xyz, "xyz");
        double total = xyz[0] + xyz[1] + xyz[2];
        if (total <= 1e-9) return new double[] {0.3127, 0.3290};
        return new double[] {xyz[0] / total, xyz[1] / total};
    }

    static double mccamyCct(double x, double y) {
        double denom = y - 0.1858;
        if (Math.abs(denom) < 1e-9) denom = denom < 0 ? -1e-9 : 1e-9;
        double n = (x - 0.332) / denom;
        return -449.0 * n * n * n + 3525.0 * n * n - 6823.3 * n + 5520.33;
    }

    private static double illuminantKelvin(int value) {
        switch (value) {
            case 1: return 6504;
            case 2: return 4230;
            case 3: return 2856;
            case 4: return 5500;
            case 9: return 5500;
            case 10: return 6500;
            case 11: return 7500;
            case 12: return 6430;
            case 13: return 5000;
            case 14: return 4230;
            case 15: return 3450;
            case 17: return 2856;
            case 18: return 4874;
            case 19: return 6774;
            case 20: return 5503;
            case 21: return 6504;
            case 22: return 7504;
            case 23: return 5003;
            case 24: return 3200;
            default: throw new IllegalArgumentException("unsupported reference illuminant: " + value);
        }
    }

    private static double[] lerp(double[] a, double[] b, double f) {
        if (a.length != b.length) throw new IllegalArgumentException("lerp length mismatch");
        double[] out = new double[a.length];
        for (int i = 0; i < a.length; i++) out[i] = a[i] * (1.0 - f) + b[i] * f;
        return out;
    }

    /** Row-major 3x3 matrix multiplication. */
    private static double[] multiply3x3(double[] a, double[] b) {
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

    /** Row-major matrix-vector multiplication. */
    private static double[] multiply3x1(double[] m, double[] v) {
        requireMatrix(m, "matrix");
        requireVector(v, "vector");
        return new double[] {
                m[0] * v[0] + m[1] * v[1] + m[2] * v[2],
                m[3] * v[0] + m[4] * v[1] + m[5] * v[2],
                m[6] * v[0] + m[7] * v[1] + m[8] * v[2]
        };
    }

    private static double[] inverse3(double[] m) {
        requireMatrix(m, "matrix");
        double a=m[0], b=m[1], c=m[2], d=m[3], e=m[4], f=m[5], g=m[6], h=m[7], i=m[8];
        double A=e*i-f*h, B=-(d*i-f*g), C=d*h-e*g;
        double D=-(b*i-c*h), E=a*i-c*g, F=-(a*h-b*g);
        double G=b*f-c*e, H=-(a*f-c*d), I=a*e-b*d;
        double det = a*A + b*B + c*C;
        if (!Double.isFinite(det) || Math.abs(det) < 1e-15) {
            throw new IllegalArgumentException("3x3 matrix is singular");
        }
        double s = 1.0 / det;
        return new double[] {A*s, D*s, G*s, B*s, E*s, H*s, C*s, F*s, I*s};
    }

    private static void requireMatrix(double[] m, String name) {
        if (m == null || m.length != 9) throw new IllegalArgumentException(name + " must contain 9 values");
        for (double v : m) if (!Double.isFinite(v)) throw new IllegalArgumentException(name + " contains non-finite values");
    }

    private static void requireVector(double[] v, String name) {
        if (v == null || v.length != 3) throw new IllegalArgumentException(name + " must contain 3 values");
        for (double x : v) if (!Double.isFinite(x)) throw new IllegalArgumentException(name + " contains non-finite values");
    }
}
