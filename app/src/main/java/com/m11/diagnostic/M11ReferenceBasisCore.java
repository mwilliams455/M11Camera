package com.m11.diagnostic;

/**
 * Provisional XYZ-D50 -> M11 Standard-A reference-camera basis bridge.
 *
 * Evidence status: STRONG INFERENCE, not firmware-proven.  This is a numerical
 * port of renderer/m11_core/reference_basis.py and must remain replaceable.
 */
public final class M11ReferenceBasisCore {
    private M11ReferenceBasisCore() {}

    public static final double[] M11_COLOR_MATRIX_A = {
            0.57568359375, -0.13330078125, -0.01611328125,
            -0.607421875, 1.5380859375, 0.435791015625,
            -0.098388671875, 0.194580078125, 0.85546875
    };

    private static final double D50_X = 0.34567;
    private static final double D50_Y = 0.35850;
    private static final double A_X = 0.44757;
    private static final double A_Y = 0.40745;

    private static final double[] BRADFORD = {
            0.8951, 0.2664, -0.1614,
            -0.7502, 1.7135, 0.0367,
            0.0389, -0.0685, 1.0296
    };

    /** Regression target recorded from the genuine-M11 DNG validation path. */
    public static final double[] RECORDED_XYZ_D50_TO_M11_A_WB = {
            1.31879337, -0.14831682, -0.14939568,
            -0.51395518, 1.34347843, 0.18430135,
            -0.27544169, 0.50342179, 0.92362240
    };

    public static double[] xyzD50ToM11AReferenceWb() {
        return inverse3(m11AWbCameraToXyzD50());
    }

    public static double[] applyXyzD50ToM11Reference(double[] xyz) {
        if (xyz == null || xyz.length != 3) throw new IllegalArgumentException("XYZ must have 3 values");
        return multiply3x1(xyzD50ToM11AReferenceWb(), xyz);
    }

    static double[] m11AWbCameraToXyzD50() {
        double[] pcsToCamera = multiply3x3(M11_COLOR_MATRIX_A, bradfordMap(D50_X, D50_Y, A_X, A_Y));
        double[] d50Xyz = xyToXyz(D50_X, D50_Y);
        double[] saturationProbe = multiply3x1(pcsToCamera, d50Xyz);
        double reachSaturationScale = Math.max(saturationProbe[0], Math.max(saturationProbe[1], saturationProbe[2]));
        for (int k = 0; k < 9; k++) pcsToCamera[k] /= reachSaturationScale;
        double[] cameraToPcs = inverse3(pcsToCamera);
        double[] cameraWhite = m11ACameraWhite();
        double[] whiteDiagonal = {
                cameraWhite[0], 0, 0,
                0, cameraWhite[1], 0,
                0, 0, cameraWhite[2]
        };
        return multiply3x3(cameraToPcs, whiteDiagonal);
    }

    static double[] m11ACameraWhite() {
        double[] white = multiply3x1(M11_COLOR_MATRIX_A, xyToXyz(A_X, A_Y));
        double max = Math.max(white[0], Math.max(white[1], white[2]));
        for (int k = 0; k < 3; k++) {
            white[k] /= max;
            white[k] = Math.max(0.001, Math.min(1.0, white[k]));
        }
        return white;
    }

    /** Adobe DNG MapWhiteMatrix direction: white1 -> white2. */
    static double[] bradfordMap(double x1, double y1, double x2, double y2) {
        double[] w1 = multiply3x1(BRADFORD, xyToXyz(x1, y1));
        double[] w2 = multiply3x1(BRADFORD, xyToXyz(x2, y2));
        double[] ratio = new double[3];
        for (int k = 0; k < 3; k++) {
            double r = w1[k] > 0.0 ? w2[k] / w1[k] : 10.0;
            ratio[k] = Math.max(0.1, Math.min(10.0, r));
        }
        double[] diagonal = {
                ratio[0], 0, 0,
                0, ratio[1], 0,
                0, 0, ratio[2]
        };
        return multiply3x3(multiply3x3(inverse3(BRADFORD), diagonal), BRADFORD);
    }

    static double[] xyToXyz(double x, double y) {
        return new double[] {x / y, 1.0, (1.0 - x - y) / y};
    }

    private static double[] multiply3x3(double[] a, double[] b) {
        if (a.length != 9 || b.length != 9) throw new IllegalArgumentException("3x3 matrix required");
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

    private static double[] multiply3x1(double[] m, double[] v) {
        if (m.length != 9 || v.length != 3) throw new IllegalArgumentException("3x3 * 3x1 required");
        return new double[] {
                m[0]*v[0] + m[1]*v[1] + m[2]*v[2],
                m[3]*v[0] + m[4]*v[1] + m[5]*v[2],
                m[6]*v[0] + m[7]*v[1] + m[8]*v[2]
        };
    }

    private static double[] inverse3(double[] m) {
        if (m.length != 9) throw new IllegalArgumentException("3x3 matrix required");
        double a=m[0], b=m[1], c=m[2], d=m[3], e=m[4], f=m[5], g=m[6], h=m[7], i=m[8];
        double A=e*i-f*h, B=-(d*i-f*g), C=d*h-e*g;
        double D=-(b*i-c*h), E=a*i-c*g, F=-(a*h-b*g);
        double G=b*f-c*e, H=-(a*f-c*d), I=a*e-b*d;
        double det = a*A + b*B + c*C;
        if (!Double.isFinite(det) || Math.abs(det) < 1e-15) throw new IllegalArgumentException("singular 3x3 matrix");
        double s = 1.0 / det;
        return new double[] {A*s, D*s, G*s, B*s, E*s, H*s, C*s, F*s, I*s};
    }
}
