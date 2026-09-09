package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.util.Base64;
import org.junit.Test;

/**
 * Cross-language parity gate.
 *
 * CI generates m11_python_android_parity_v1.b64 immediately before Gradle by
 * running tools/generate_m11_android_python_parity_fixture.py against the frozen
 * Python reference renderer. This test then verifies the Android Java core stage
 * by stage against those freshly generated Python values.
 */
public final class M11PythonAndroidParityTest {
    private static final byte[] MAGIC = {'M','1','1','P','A','R','1','A'};
    private static final double EPS = 3e-12;

    @Test
    public void javaCoreMatchesFreshPythonStageOracle() throws Exception {
        InputStream resource = getClass().getClassLoader().getResourceAsStream("m11_python_android_parity_v1.b64");
        assertNotNull("CI must generate Python parity fixture before Gradle tests", resource);
        byte[] encoded = resource.readAllBytes();
        byte[] raw = Base64.getMimeDecoder().decode(encoded);
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw));

        byte[] magic = new byte[8];
        in.readFully(magic);
        assertArrayEquals(MAGIC, magic);
        assertEquals(1, in.readInt());
        int caseCount = in.readInt();
        assertEquals(147, caseCount);

        M11ReferenceRendererCore.Tables tables = syntheticTables();
        for (int caseIndex = 0; caseIndex < caseCount; caseIndex++) {
            int modeId = in.readUnsignedByte();
            int flags = in.readUnsignedByte();
            assertEquals(0, in.readUnsignedShort());

            double[] input = read3(in);
            double[] expectedAfterCc0 = read3(in);
            double expectedToneY = in.readDouble();
            double expectedToneY2 = in.readDouble();
            double expectedToneScale = in.readDouble();
            double[] expectedAfterTone = read3(in);
            double[] expectedAfterCc1 = read3(in);
            boolean expectedHasYcc = in.readInt() != 0;
            double[] expectedYccBefore = read3(in);
            double[] expectedYccAfter = read3(in);
            double[] expectedOutput = read3(in);

            M11ReferenceRendererCore.Mode mode = switch (modeId) {
                case 0 -> M11ReferenceRendererCore.Mode.NATURAL;
                case 1 -> M11ReferenceRendererCore.Mode.STANDARD;
                case 2 -> M11ReferenceRendererCore.Mode.VIVID;
                default -> throw new AssertionError("unexpected mode id " + modeId);
            };
            M11ReferenceRendererCore.RenderConfig cfg = new M11ReferenceRendererCore.RenderConfig(
                    mode,
                    bit(flags, 0), bit(flags, 1), bit(flags, 2),
                    bit(flags, 3), bit(flags, 4), bit(flags, 5));

            M11ReferenceRendererCore.StageTrace actual = M11ReferenceRendererCore.renderPixelTrace(
                    input[0], input[1], input[2], tables, cfg);
            String prefix = "case " + caseIndex + " mode=" + mode + " flags=0x" + Integer.toHexString(flags) + ": ";
            assertArrayClose(prefix + "afterCc0", expectedAfterCc0, actual.afterCc0);
            assertEquals(prefix + "toneLumaInput", expectedToneY, actual.toneLumaInput, EPS);
            assertEquals(prefix + "toneLumaOutput", expectedToneY2, actual.toneLumaOutput, EPS);
            assertEquals(prefix + "toneScale", expectedToneScale, actual.toneScale, EPS);
            assertArrayClose(prefix + "afterTone", expectedAfterTone, actual.afterTone);
            assertArrayClose(prefix + "afterCc1", expectedAfterCc1, actual.afterCc1);
            if (expectedHasYcc) {
                assertNotNull(prefix + "yccBefore", actual.yccBeforeGammaChroma);
                assertNotNull(prefix + "yccAfter", actual.yccAfterGammaChroma);
                assertArrayClose(prefix + "yccBefore", expectedYccBefore, actual.yccBeforeGammaChroma);
                assertArrayClose(prefix + "yccAfter", expectedYccAfter, actual.yccAfterGammaChroma);
            } else {
                assertNull(prefix + "yccBefore", actual.yccBeforeGammaChroma);
                assertNull(prefix + "yccAfter", actual.yccAfterGammaChroma);
            }
            assertArrayClose(prefix + "output", expectedOutput, actual.output);
        }
        assertEquals("unexpected parity fixture trailer", 0, in.available());
    }

    private static boolean bit(int flags, int bit) {
        return (flags & (1 << bit)) != 0;
    }

    private static double[] read3(DataInputStream in) throws Exception {
        return new double[] {in.readDouble(), in.readDouble(), in.readDouble()};
    }

    private static void assertArrayClose(String message, double[] expected, double[] actual) {
        assertEquals(message + " length", expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(message + "[" + i + "]", expected[i], actual[i], EPS);
        }
    }

    private static M11ReferenceRendererCore.Tables syntheticTables() {
        double[] cc0 = q9(new int[] {495,-58,63,10,601,-111,49,-255,705});
        double[] cc1 = q9(new int[] {1041,-372,-157,-117,630,-1,-4,-78,595});

        double[] toneX = new double[17];
        double[][] tone = new double[7][17];
        for (int i = 0; i < toneX.length; i++) toneX[i] = i / 16.0;
        for (int contrast = -3; contrast <= 3; contrast++) {
            double exponent = 1.0 - 0.055 * contrast;
            double scale = 1.0 + 0.025 * contrast;
            for (int i = 0; i < toneX.length; i++) {
                tone[contrast + 3][i] = Math.max(0.0, Math.min(1.25, Math.pow(toneX[i], exponent) * scale));
            }
        }

        double[] gammaX = new double[33];
        double[] gammaY = new double[33];
        for (int i = 0; i < gammaX.length; i++) {
            gammaX[i] = i / 32.0;
            gammaY[i] = Math.pow(gammaX[i], 1.0 / 2.15);
        }
        return new M11ReferenceRendererCore.Tables(cc0, cc1, toneX, tone, gammaX, gammaY);
    }

    private static double[] q9(int[] values) {
        double[] out = new double[values.length];
        for (int i = 0; i < values.length; i++) out[i] = values[i] / 512.0;
        return out;
    }
}
