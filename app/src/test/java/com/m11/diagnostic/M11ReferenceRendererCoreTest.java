package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class M11ReferenceRendererCoreTest {
    private static final double[] IDENTITY = {1,0,0, 0,1,0, 0,0,1};

    private static M11ReferenceRendererCore.Tables identityTables() {
        double[] axis = {0.0, 1.0};
        double[][] tone = new double[7][];
        for (int i = 0; i < 7; i++) tone[i] = new double[] {0.0, 1.0};
        return new M11ReferenceRendererCore.Tables(
                IDENTITY, IDENTITY, axis, tone, axis, new double[] {0.0, 1.0});
    }

    @Test
    public void neutralGrayIsInvariantAcrossCreativeModesWithIdentityCurves() {
        M11ReferenceRendererCore.Tables t = identityTables();
        for (M11ReferenceRendererCore.Mode mode : M11ReferenceRendererCore.Mode.values()) {
            double[] out = M11ReferenceRendererCore.renderPixel(
                    0.4, 0.4, 0.4, t, M11ReferenceRendererCore.RenderConfig.full(mode));
            assertArrayEquals(new double[] {0.4, 0.4, 0.4}, out, 1e-12);
        }
    }

    @Test
    public void standardChromaStageMatchesFrozenYccMath() {
        M11ReferenceRendererCore.Tables t = identityTables();
        M11ReferenceRendererCore.RenderConfig cfg = new M11ReferenceRendererCore.RenderConfig(
                M11ReferenceRendererCore.Mode.STANDARD,
                false, false, false, false, true, false);
        double[] out = M11ReferenceRendererCore.renderPixel(0.5, 0.2, 0.1, t, cfg);
        assertArrayEquals(new double[] {
                0.5331640625,
                0.1881640625,
                0.0731640625
        }, out, 1e-12);
    }

    @Test
    public void scalarToneModelScalesRgbByYoutOverYin() {
        double[] axis = {0.0, 1.0};
        double[][] tone = new double[7][];
        for (int i = 0; i < 7; i++) tone[i] = new double[] {0.0, 1.0};
        // Standard state 0 is index 3.  Make its output curve exactly half input.
        tone[3] = new double[] {0.0, 0.5};
        M11ReferenceRendererCore.Tables t = new M11ReferenceRendererCore.Tables(
                IDENTITY, IDENTITY, axis, tone, axis, new double[] {0.0, 1.0});
        M11ReferenceRendererCore.RenderConfig cfg = new M11ReferenceRendererCore.RenderConfig(
                M11ReferenceRendererCore.Mode.STANDARD,
                false, true, false, false, false, false);

        M11ReferenceRendererCore.StageTrace trace = M11ReferenceRendererCore.renderPixelTrace(
                0.6, 0.3, 0.15, t, cfg);
        assertEquals(0.5, trace.toneScale, 1e-15);
        assertEquals(trace.toneLumaInput * 0.5, trace.toneLumaOutput, 1e-15);
        assertArrayEquals(new double[] {0.3, 0.15, 0.075}, trace.output, 1e-15);
        assertNull(trace.yccBeforeGammaChroma);
        assertNull(trace.yccAfterGammaChroma);
    }

    @Test
    public void stageTraceShowsYOnlyGammaThenCreativeChroma() {
        double[] axis = {0.0, 1.0};
        double[][] tone = new double[7][];
        for (int i = 0; i < 7; i++) tone[i] = new double[] {0.0, 1.0};
        M11ReferenceRendererCore.Tables t = new M11ReferenceRendererCore.Tables(
                IDENTITY, IDENTITY, axis, tone, axis, new double[] {0.0, 0.5});
        M11ReferenceRendererCore.RenderConfig cfg = new M11ReferenceRendererCore.RenderConfig(
                M11ReferenceRendererCore.Mode.VIVID,
                false, false, false, true, true, false);
        M11ReferenceRendererCore.StageTrace trace = M11ReferenceRendererCore.renderPixelTrace(
                0.5, 0.2, 0.1, t, cfg);

        assertEquals(trace.yccBeforeGammaChroma[0] * 0.5, trace.yccAfterGammaChroma[0], 1e-15);
        assertEquals(trace.yccBeforeGammaChroma[1] * 1.30, trace.yccAfterGammaChroma[1], 1e-15);
        assertEquals(trace.yccBeforeGammaChroma[2] * 1.30, trace.yccAfterGammaChroma[2], 1e-15);
    }

    @Test
    public void interpolationMatchesNumpyStyleClampedLinearBehavior() {
        double[] x = {0.0, 0.25, 1.0};
        double[] y = {0.0, 0.5, 1.0};
        assertEquals(0.0, M11ReferenceRendererCore.interpolate(-1.0, x, y), 0.0);
        assertEquals(0.25, M11ReferenceRendererCore.interpolate(0.125, x, y), 1e-15);
        assertEquals(0.75, M11ReferenceRendererCore.interpolate(0.625, x, y), 1e-15);
        assertEquals(1.0, M11ReferenceRendererCore.interpolate(2.0, x, y), 0.0);
    }
}
