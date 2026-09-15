package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

import org.junit.Test;

public final class M11InternalEntryCoreTest {
    private static final double EPS = 1e-12;

    private static final double[] XIAOMI_S = {
            1.9584339, 0.10974634, 0.353397,
            0.6746988, 0.7578125, 0.03773585,
            -0.12001274, -0.45136034, 2.1175075
    };

    private static final double[] HISTORICAL_CC0 = {
            495.0 / 512.0, -58.0 / 512.0, 63.0 / 512.0,
            10.0 / 512.0, 601.0 / 512.0, -111.0 / 512.0,
            49.0 / 512.0, -255.0 / 512.0, 705.0 / 512.0
    };

    @Test
    public void pcsToInternalMatchesFirmwareClosedK() {
        assertArrayEquals(new double[] {
                1.3460, -0.2556, -0.0511,
                -0.5446, 1.5082, 0.0205,
                0.0, 0.0, 1.2123
        }, M11InternalEntryCore.PCS_TO_INTERNAL, 0.0);
    }

    @Test
    public void xiaomiCameraToInternalMatchesPythonReference() {
        double[] actual = M11InternalEntryCore.cameraToInternal(XIAOMI_S);
        double[] expected = {
                2.469731667134, -0.022913787986, 0.357822445490,
                -0.051442632950, 1.073912068766, -0.092137893480,
                -0.145491444702, -0.547184140182, 2.567054342250
        };
        assertArrayEquals(expected, actual, 1e-12);
    }

    @Test
    public void identityCc0ClonePreservesOtherTablesAndDoesNotMutateSource() {
        double[] x = {0.0, 0.5, 1.0};
        double[][] tone = new double[7][3];
        for (int i = 0; i < tone.length; i++) {
            tone[i][0] = 0.0;
            tone[i][1] = 0.4 + i * 0.01;
            tone[i][2] = 1.0;
        }
        double[] cc1 = {
                1.01, -0.01, 0.0,
                0.0, 1.02, -0.02,
                -0.01, 0.0, 1.01
        };
        M11ReferenceRendererCore.Tables source = new M11ReferenceRendererCore.Tables(
                HISTORICAL_CC0, cc1, x, tone, x, new double[] {0.0, 0.7, 1.0});
        M11ReferenceRendererCore.Tables clone = M11InternalEntryCore.withIdentityCc0(source);

        assertNotSame(source, clone);
        assertArrayEquals(M11InternalEntryCore.IDENTITY_CC0, clone.cc0, 0.0);
        assertArrayEquals(HISTORICAL_CC0, source.cc0, 0.0);
        assertArrayEquals(source.cc1, clone.cc1, 0.0);
        assertArrayEquals(source.toneX, clone.toneX, 0.0);
        assertArrayEquals(source.gammaX, clone.gammaX, 0.0);
        assertArrayEquals(source.gammaY, clone.gammaY, 0.0);
        for (int i = 0; i < source.toneCurves.length; i++) {
            assertArrayEquals(source.toneCurves[i], clone.toneCurves[i], 0.0);
        }
    }

    @Test
    public void effectiveEntryComparisonMatchesPythonReference() {
        double[] oldPreCc0 = M11InternalEntryCore.multiply3x3(
                M11ReferenceBasisCore.xyzD50ToM11AReferenceWb(), XIAOMI_S);
        M11InternalEntryCore.Comparison c = M11InternalEntryCore.compareEffectiveEntries(
                XIAOMI_S, oldPreCc0, HISTORICAL_CC0);

        assertEquals(0.9655747553431321, c.bestScalarOldToDirect, 1e-12);
        assertEquals(0.0505401371, c.directRelativeEv, 1e-10);
        assertEquals(0.0223847180, c.maxAbsResidualAfterScalar, 2e-8);
        assertEquals(0.0119669550, c.rmsResidualAfterScalar, 2e-8);
    }

    @Test
    public void matrixMultiplyIsRowMajorAndIdentitySafe() {
        double[] actual = M11InternalEntryCore.multiply3x3(M11InternalEntryCore.IDENTITY_CC0, XIAOMI_S);
        assertArrayEquals(XIAOMI_S, actual, EPS);
    }
}
