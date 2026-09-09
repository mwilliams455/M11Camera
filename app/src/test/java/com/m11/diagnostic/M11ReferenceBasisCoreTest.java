package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public final class M11ReferenceBasisCoreTest {
    @Test
    public void reconstructedBridgeMatchesRecordedM11RegressionMatrix() {
        double[] actual = M11ReferenceBasisCore.xyzD50ToM11AReferenceWb();
        assertArrayEquals(M11ReferenceBasisCore.RECORDED_XYZ_D50_TO_M11_A_WB, actual, 1e-8);
    }

    @Test
    public void applyUsesSameRowMajorBridge() {
        double[] m = M11ReferenceBasisCore.xyzD50ToM11AReferenceWb();
        double[] xyz = {0.3, 0.4, 0.2};
        double[] expected = {
                m[0]*xyz[0] + m[1]*xyz[1] + m[2]*xyz[2],
                m[3]*xyz[0] + m[4]*xyz[1] + m[5]*xyz[2],
                m[6]*xyz[0] + m[7]*xyz[1] + m[8]*xyz[2]
        };
        assertArrayEquals(expected, M11ReferenceBasisCore.applyXyzD50ToM11Reference(xyz), 0.0);
    }
}
