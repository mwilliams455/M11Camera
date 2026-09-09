package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class M11MatrixCoreTest {
    @Test
    public void correctedThirdSroTargetIsFrozen() {
        assertArrayEquals(new int[] {
                212, -165, -71,
                -73, 676, 85,
                -27, 174, 285
        }, M11MatrixCore.SRO_THIRD_Q9);
    }

    @Test
    public void quantizerRoundsHalfAwayFromZero() {
        assertEquals(213, M11MatrixCore.quantizeQ9(212.5 / 512.0));
        assertEquals(-213, M11MatrixCore.quantizeQ9(-212.5 / 512.0));
        assertEquals(212, M11MatrixCore.quantizeQ9(212.499 / 512.0));
        assertEquals(-212, M11MatrixCore.quantizeQ9(-212.499 / 512.0));
    }

    @Test
    public void thirdSroDequantizationMatchesRecoveredFloats() {
        double[] actual = M11MatrixCore.dequantizeMatrix(M11MatrixCore.SRO_THIRD_Q9);
        double[] expected = {
                0.4140625, -0.322265625, -0.138671875,
                -0.142578125, 1.3203125, 0.166015625,
                -0.052734375, 0.33984375, 0.556640625
        };
        assertArrayEquals(expected, actual, 0.0);
    }

    @Test
    public void identityRecordLeavesRgbUnchanged() {
        double[] actual = M11MatrixCore.applyQ9(M11MatrixCore.SRO_IDENTITY_Q9, 0.1, 0.5, 0.9);
        assertArrayEquals(new double[] {0.1, 0.5, 0.9}, actual, 0.0);
    }
}
