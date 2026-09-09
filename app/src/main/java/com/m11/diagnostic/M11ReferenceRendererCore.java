package com.m11.diagnostic;

import java.util.Arrays;

/**
 * Android port of the frozen M11 reference-renderer pixel math.
 *
 * Evidence boundary:
 * - CC0/CC1/YCC numeric records and mode states are firmware-derived inputs.
 * - Category-6 tone is represented using the recorded scalar-gain model.
 * - Gamma-on-Y placement remains a frozen reference-model assumption.
 * - The separate third SRO matrix is intentionally NOT applied here because its
 *   pixel-domain consumer placement remains unresolved.
 */
public final class M11ReferenceRendererCore {
    private M11ReferenceRendererCore() {}

    public static final double[] YCC_MATRIX = {
            77.0 / 256.0, 150.0 / 256.0, 29.0 / 256.0,
            -43.0 / 256.0, -85.0 / 256.0, 128.0 / 256.0,
            128.0 / 256.0, -107.0 / 256.0, -21.0 / 256.0
    };
    public static final double[] YCC_INVERSE = inverse3(YCC_MATRIX);
    public static final double[] TONE_LUMA = {77.0 / 255.0, 149.0 / 255.0, 29.0 / 255.0};

    public enum Mode {
        NATURAL(-1, 1.00),
        STANDARD(0, 1.15),
        VIVID(+1, 1.30);

        public final int contrastState;
        public final double chromaScale;

        Mode(int contrastState, double chromaScale) {
            this.contrastState = contrastState;
            this.chromaScale = chromaScale;
        }
    }

    public static final class Tables {
        public final double[] cc0;
        public final double[] cc1;
        public final double[] toneX;
        /** toneCurves[state + 3][sample] stores modeled output-normalized Y. */
        public final double[][] toneCurves;
        public final double[] gammaX;
        public final double[] gammaY;

        public Tables(double[] cc0, double[] cc1, double[] toneX, double[][] toneCurves,
                      double[] gammaX, double[] gammaY) {
            this.cc0 = copyMatrix(cc0, "cc0");
            this.cc1 = copyMatrix(cc1, "cc1");
            this.toneX = copyAxis(toneX, "toneX");
            if (toneCurves == null || toneCurves.length != 7) {
                throw new IllegalArgumentException("toneCurves must contain seven contrast states -3..+3");
            }
            this.toneCurves = new double[7][];
            for (int i = 0; i < 7; i++) {
                this.toneCurves[i] = copyCurve(toneCurves[i], this.toneX.length, "toneCurves[" + i + "]");
            }
            this.gammaX = copyAxis(gammaX, "gammaX");
            this.gammaY = copyCurve(gammaY, this.gammaX.length, "gammaY");
        }

        public double[] toneCurve(int contrastState) {
            if (contrastState < -3 || contrastState > 3) {
                throw new IllegalArgumentException("contrast state must be -3..+3");
            }
            return toneCurves[contrastState + 3];
        }
    }

    public static final class RenderConfig {
        public final Mode mode;
        public final boolean useCc0;
        public final boolean useTone;
        public final boolean useCc1;
        public final boolean useGamma;
        public final boolean useChroma;
        public final boolean clamp;

        public RenderConfig(Mode mode, boolean useCc0, boolean useTone, boolean useCc1,
                            boolean useGamma, boolean useChroma, boolean clamp) {
            if (mode == null) throw new IllegalArgumentException("mode == null");
            this.mode = mode;
            this.useCc0 = useCc0;
            this.useTone = useTone;
            this.useCc1 = useCc1;
            this.useGamma = useGamma;
            this.useChroma = useChroma;
            this.clamp = clamp;
        }

        public static RenderConfig full(Mode mode) {
            return new RenderConfig(mode, true, true, true, true, true, true);
        }
    }

    /** Stage-wise diagnostic record for one pixel. Arrays are defensive copies. */
    public static final class StageTrace {
        public final double[] input;
        public final double[] afterCc0;
        public final double toneLumaInput;
        public final double toneLumaOutput;
        public final double toneScale;
        public final double[] afterTone;
        public final double[] afterCc1;
        public final double[] yccBeforeGammaChroma;
        public final double[] yccAfterGammaChroma;
        public final double[] output;

        StageTrace(double[] input, double[] afterCc0, double toneLumaInput,
                   double toneLumaOutput, double toneScale, double[] afterTone,
                   double[] afterCc1, double[] yccBeforeGammaChroma,
                   double[] yccAfterGammaChroma, double[] output) {
            this.input = input.clone();
            this.afterCc0 = afterCc0.clone();
            this.toneLumaInput = toneLumaInput;
            this.toneLumaOutput = toneLumaOutput;
            this.toneScale = toneScale;
            this.afterTone = afterTone.clone();
            this.afterCc1 = afterCc1.clone();
            this.yccBeforeGammaChroma = yccBeforeGammaChroma == null ? null : yccBeforeGammaChroma.clone();
            this.yccAfterGammaChroma = yccAfterGammaChroma == null ? null : yccAfterGammaChroma.clone();
            this.output = output.clone();
        }
    }

    public static double[] renderPixel(double r, double g, double b, Tables tables, RenderConfig config) {
        return renderPixelTrace(r, g, b, tables, config).output;
    }

    public static StageTrace renderPixelTrace(double r, double g, double b, Tables tables, RenderConfig config) {
        if (tables == null || config == null) throw new IllegalArgumentException("tables/config must not be null");
        double[] input = {r, g, b};
        requireFinite(input, "input");
        double[] out = input.clone();

        if (config.useCc0) out = multiply3x1(tables.cc0, out);
        double[] afterCc0 = out.clone();

        double toneY = dot(out, TONE_LUMA);
        double toneY2 = toneY;
        double toneScale = 1.0;
        if (config.useTone) {
            double lookup = clamp01(toneY);
            toneY2 = interpolate(lookup, tables.toneX, tables.toneCurve(config.mode.contrastState));
            if (toneY > 1e-10) {
                toneScale = toneY2 / Math.max(toneY, 1e-10);
                out[0] *= toneScale;
                out[1] *= toneScale;
                out[2] *= toneScale;
            }
        }
        double[] afterTone = out.clone();

        if (config.useCc1) out = multiply3x1(tables.cc1, out);
        double[] afterCc1 = out.clone();

        double[] yccBefore = null;
        double[] yccAfter = null;
        if (config.useGamma || config.useChroma) {
            double[] ycc = multiply3x1(YCC_MATRIX, out);
            yccBefore = ycc.clone();
            if (config.useGamma) {
                ycc[0] = interpolate(clamp01(ycc[0]), tables.gammaX, tables.gammaY);
            }
            if (config.useChroma) {
                ycc[1] *= config.mode.chromaScale;
                ycc[2] *= config.mode.chromaScale;
            }
            yccAfter = ycc.clone();
            out = multiply3x1(YCC_INVERSE, ycc);
        }

        if (config.clamp) {
            out[0] = clamp01(out[0]);
            out[1] = clamp01(out[1]);
            out[2] = clamp01(out[2]);
        }
        requireFinite(out, "output");
        return new StageTrace(input, afterCc0, toneY, toneY2, toneScale,
                afterTone, afterCc1, yccBefore, yccAfter, out);
    }

    /**
     * Render interleaved RGB values in-place-compatible form.  Input/output are
     * code-independent normalized values; no sRGB OETF is added here.
     */
    public static double[] renderRgbBuffer(double[] interleavedRgb, Tables tables, RenderConfig config) {
        if (interleavedRgb == null || interleavedRgb.length % 3 != 0) {
            throw new IllegalArgumentException("RGB buffer length must be divisible by 3");
        }
        double[] output = new double[interleavedRgb.length];
        for (int i = 0; i < interleavedRgb.length; i += 3) {
            double[] p = renderPixel(interleavedRgb[i], interleavedRgb[i + 1], interleavedRgb[i + 2], tables, config);
            output[i] = p[0];
            output[i + 1] = p[1];
            output[i + 2] = p[2];
        }
        return output;
    }

    static double interpolate(double x, double[] axis, double[] values) {
        if (axis.length != values.length || axis.length < 2) throw new IllegalArgumentException("invalid interpolation table");
        if (x <= axis[0]) return values[0];
        int last = axis.length - 1;
        if (x >= axis[last]) return values[last];

        int lo = 0;
        int hi = last;
        while (hi - lo > 1) {
            int mid = (lo + hi) >>> 1;
            if (axis[mid] <= x) lo = mid;
            else hi = mid;
        }
        double span = axis[hi] - axis[lo];
        if (!(span > 0.0)) throw new IllegalArgumentException("interpolation axis must be strictly increasing");
        double f = (x - axis[lo]) / span;
        return values[lo] * (1.0 - f) + values[hi] * f;
    }

    private static double dot(double[] a, double[] b) {
        return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    }

    private static double[] multiply3x1(double[] m, double[] v) {
        return new double[] {
                m[0] * v[0] + m[1] * v[1] + m[2] * v[2],
                m[3] * v[0] + m[4] * v[1] + m[5] * v[2],
                m[6] * v[0] + m[7] * v[1] + m[8] * v[2]
        };
    }

    private static double[] inverse3(double[] m) {
        double a=m[0], b=m[1], c=m[2], d=m[3], e=m[4], f=m[5], g=m[6], h=m[7], i=m[8];
        double A=e*i-f*h, B=-(d*i-f*g), C=d*h-e*g;
        double D=-(b*i-c*h), E=a*i-c*g, F=-(a*h-b*g);
        double G=b*f-c*e, H=-(a*f-c*d), I=a*e-b*d;
        double det = a*A + b*B + c*C;
        if (!Double.isFinite(det) || Math.abs(det) < 1e-15) throw new IllegalArgumentException("singular 3x3 matrix");
        double s = 1.0 / det;
        return new double[] {A*s, D*s, G*s, B*s, E*s, H*s, C*s, F*s, I*s};
    }

    private static double clamp01(double x) {
        return Math.max(0.0, Math.min(1.0, x));
    }

    private static double[] copyMatrix(double[] value, String name) {
        if (value == null || value.length != 9) throw new IllegalArgumentException(name + " must contain 9 values");
        requireFinite(value, name);
        return value.clone();
    }

    private static double[] copyAxis(double[] value, String name) {
        if (value == null || value.length < 2) throw new IllegalArgumentException(name + " must contain at least 2 values");
        requireFinite(value, name);
        double[] out = value.clone();
        for (int i = 1; i < out.length; i++) {
            if (!(out[i] > out[i - 1])) throw new IllegalArgumentException(name + " must be strictly increasing");
        }
        return out;
    }

    private static double[] copyCurve(double[] value, int expected, String name) {
        if (value == null || value.length != expected) throw new IllegalArgumentException(name + " length mismatch");
        requireFinite(value, name);
        return value.clone();
    }

    private static void requireFinite(double[] value, String name) {
        for (double x : value) if (!Double.isFinite(x)) throw new IllegalArgumentException(name + " contains non-finite values: " + Arrays.toString(value));
    }
}
