package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class M11SourceAdapterCoreTest {
    private static final double[] CM1_D65 = {
            0.8359375, -0.1718750, -0.1328125,
            -0.4687500, 1.3984375, 0.0468750,
            -0.0859375, 0.3359375, 0.4062500
    };

    private static final double[] CM2_A = {
            1.2812500, -0.4843750, -0.2265625,
            -0.5859375, 1.5937500, 0.1406250,
            -0.0468750, 0.1796875, 0.7031250
    };

    private static final double[] CAL = {
            1.03125, 0, 0,
            0, 1, 0,
            0, 0, 1.015625
    };

    private static final double[] FM = {
            0.6328125, 0.1093750, 0.2187500,
            0.2187500, 0.7578125, 0.0234375,
            -0.0390625, -0.4531250, 1.3203125
    };

    private static final double[] NEUTRAL = {0.32421875, 1.0, 0.62109375};

    @Test
    public void currentXiaomiMainFixtureMatchesValidatedInterpolationFactor() {
        double factor = M11SourceAdapterCore.findDngInterpolationFactor(
                21, 17, CAL, CAL, CM1_D65, CM2_A, NEUTRAL);
        assertEquals(0.00006103515625, factor, 0.0);
    }

    @Test
    public void currentXiaomiMainFixtureMatchesDeviceSourcecal2aTransform() {
        M11SourceAdapterCore.Result result = M11SourceAdapterCore.buildDualIlluminantTransform(
                21, 17, CAL, CAL, CM1_D65, CM2_A, FM, FM, NEUTRAL);

        double[] expected = {
                1.9584339, 0.10974634, 0.3533970,
                0.6746988, 0.75781250, 0.03773585,
                -0.12001274, -0.45136034, 2.1175075
        };
        assertArrayEquals(expected, result.cameraToXyzD50, 1e-6);
        assertEquals(0.00006103515625, result.interpolationFactor, 0.0);
    }

    @Test
    public void forwardMatrixWhiteMapsToD50AfterNormalization() {
        double[] normalized = M11SourceAdapterCore.normalizeForwardMatrix(FM);
        double[] xyz = M11SourceAdapterCore.applyCameraToXyz(
                new double[] {1.0, 1.0, 1.0}, normalized);
        assertArrayEquals(M11SourceAdapterCore.D50_XYZ, xyz, 1e-12);
    }
}
