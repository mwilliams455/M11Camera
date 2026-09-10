package com.m11.diagnostic;

import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/** On-device parity evaluator for the bundled, generated 32x32 synthetic DNG only. */
public final class M11SyntheticRawSelfTest {
    private static final String FIXTURE_ASSET = "apk1a_synthetic.dng";
    private static final String EXPECTED_MOSAIC_ASSET = "apk1a_expected_mosaic_u16le.bin";
    private static final String EXPECTED_AHD_ASSET = "apk1a_expected_ahd_u16le.bin";

    private static final String FIXTURE_SHA256 =
            "d9a2433c39f8705a0b47bb840dfbb96ccc0df16f66f542bb2af755324a26808b";
    private static final String EXPECTED_MOSAIC_SHA256 =
            "422cd91c9d5e298062c92b288e983123842b86dd6475b7d10ad6eb57c37d0fa1";
    private static final String EXPECTED_AHD_SHA256 =
            "1609ff7fc23cfff017b36f2d2956ca0b8fdac9359d372d23266ce96970e2492c";

    private static final byte[] MAGIC = new byte[] {'M','1','1','R','S','T','1',0};
    private static final int HEADER_BYTES = 40;
    private static final int EXPECTED_MOSAIC_BYTES = 32 * 32 * 2;
    private static final int EXPECTED_AHD_BYTES = 32 * 32 * 3 * 2;

    private M11SyntheticRawSelfTest() {}

    public static String run(Context context) throws Exception {
        byte[] fixture = readAsset(context, FIXTURE_ASSET);
        byte[] expectedMosaic = readAsset(context, EXPECTED_MOSAIC_ASSET);
        byte[] expectedAhd = readAsset(context, EXPECTED_AHD_ASSET);

        String fixtureHash = sha256(fixture);
        String expectedMosaicHash = sha256(expectedMosaic);
        String expectedAhdHash = sha256(expectedAhd);

        require(FIXTURE_SHA256.equals(fixtureHash), "bundled synthetic DNG SHA-256 gate failed");
        require(EXPECTED_MOSAIC_SHA256.equals(expectedMosaicHash), "bundled rawpy mosaic oracle SHA-256 gate failed");
        require(EXPECTED_AHD_SHA256.equals(expectedAhdHash), "bundled rawpy AHD oracle SHA-256 gate failed");
        require(fixture.length == 2382, "unexpected synthetic DNG byte count");
        require(expectedMosaic.length == EXPECTED_MOSAIC_BYTES, "unexpected mosaic oracle byte count");
        require(expectedAhd.length == EXPECTED_AHD_BYTES, "unexpected AHD oracle byte count");

        File cacheFile = new File(context.getCacheDir(), "m11_apk1a_synthetic_selftest.dng");
        try (FileOutputStream out = new FileOutputStream(cacheFile, false)) {
            out.write(fixture);
            out.getFD().sync();
        }

        byte[] packet;
        try (ParcelFileDescriptor pfd = ParcelFileDescriptor.open(cacheFile, ParcelFileDescriptor.MODE_READ_ONLY)) {
            packet = M11RawSelfTestBridge.runSyntheticFixture(pfd.getFd());
        }

        NativePacket decoded = NativePacket.parse(packet);
        require(decoded.mosaicWidth == 32 && decoded.mosaicHeight == 32,
                "unexpected native mosaic geometry");
        require(decoded.outputWidth == 32 && decoded.outputHeight == 32 && decoded.outputColors == 3,
                "unexpected native AHD geometry");
        require(decoded.outputBits == 16, "unexpected native AHD bit depth");

        boolean mosaicExact = Arrays.equals(decoded.mosaic, expectedMosaic);
        boolean ahdExact = Arrays.equals(decoded.ahd, expectedAhd);
        DiffStats mosaicDiff = DiffStats.compareU16LE(decoded.mosaic, expectedMosaic);
        DiffStats ahdDiff = DiffStats.compareU16LE(decoded.ahd, expectedAhd);

        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown";
        return String.format(Locale.US,
                "M11 APK1A bundled RAW parity self-test\n" +
                "fixtureSyntheticOnly=true\n" +
                "deviceAbi=%s\n" +
                "fixtureSha256=%s\n" +
                "fixtureSha256Gate=true\n" +
                "rawpyOracle=0.27.1 / LibRaw 0.22.1 / AHD\n" +
                "nativeLibRaw=0.22.1 (APK pinned build)\n" +
                "mosaicNativeSha256=%s\n" +
                "mosaicExpectedSha256=%s\n" +
                "mosaicByteExact=%s\n" +
                "mosaicDiff=%s\n" +
                "ahdNativeSha256=%s\n" +
                "ahdExpectedSha256=%s\n" +
                "ahdByteExact=%s\n" +
                "ahdDiff=%s\n" +
                "androidSyntheticMosaicParityProven=%s\n" +
                "androidSyntheticAhdByteParityProven=%s\n" +
                "realXiaomiPixelParityProven=false\n" +
                "m11RendererInvoked=false\n" +
                "userDngPixelDecodeEnabled=false",
                abi,
                fixtureHash,
                sha256(decoded.mosaic), EXPECTED_MOSAIC_SHA256,
                Boolean.toString(mosaicExact), mosaicDiff,
                sha256(decoded.ahd), EXPECTED_AHD_SHA256,
                Boolean.toString(ahdExact), ahdDiff,
                Boolean.toString(mosaicExact), Boolean.toString(ahdExact));
    }

    private static byte[] readAsset(Context context, String name) throws Exception {
        try (InputStream in = context.getAssets().open(name);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            for (int n; (n = in.read(buf)) >= 0;) {
                if (n > 0) out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte b : digest) out.append(String.format(Locale.US, "%02x", b & 0xff));
        return out.toString();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static final class NativePacket {
        final int mosaicWidth;
        final int mosaicHeight;
        final int outputWidth;
        final int outputHeight;
        final int outputColors;
        final int outputBits;
        final byte[] mosaic;
        final byte[] ahd;

        private NativePacket(int mosaicWidth, int mosaicHeight, int outputWidth, int outputHeight,
                             int outputColors, int outputBits, byte[] mosaic, byte[] ahd) {
            this.mosaicWidth = mosaicWidth;
            this.mosaicHeight = mosaicHeight;
            this.outputWidth = outputWidth;
            this.outputHeight = outputHeight;
            this.outputColors = outputColors;
            this.outputBits = outputBits;
            this.mosaic = mosaic;
            this.ahd = ahd;
        }

        static NativePacket parse(byte[] packet) {
            require(packet != null && packet.length >= HEADER_BYTES, "native self-test packet too short");
            for (int i = 0; i < MAGIC.length; ++i)
                require(packet[i] == MAGIC[i], "native self-test packet magic mismatch");

            ByteBuffer b = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN);
            b.position(8);
            int mosaicBytes = b.getInt();
            int ahdBytes = b.getInt();
            int mw = b.getInt();
            int mh = b.getInt();
            int ow = b.getInt();
            int oh = b.getInt();
            int colors = b.getInt();
            int bits = b.getInt();
            require(mosaicBytes == EXPECTED_MOSAIC_BYTES, "native mosaic byte count mismatch");
            require(ahdBytes == EXPECTED_AHD_BYTES, "native AHD byte count mismatch");
            require(packet.length == HEADER_BYTES + mosaicBytes + ahdBytes,
                    "native self-test packet total length mismatch");
            byte[] mosaic = Arrays.copyOfRange(packet, HEADER_BYTES, HEADER_BYTES + mosaicBytes);
            byte[] ahd = Arrays.copyOfRange(packet, HEADER_BYTES + mosaicBytes, packet.length);
            return new NativePacket(mw, mh, ow, oh, colors, bits, mosaic, ahd);
        }
    }

    private static final class DiffStats {
        final int differingSamples;
        final int samples;
        final int maxAbs;
        final double meanAbs;
        final double rmse;

        private DiffStats(int differingSamples, int samples, int maxAbs, double meanAbs, double rmse) {
            this.differingSamples = differingSamples;
            this.samples = samples;
            this.maxAbs = maxAbs;
            this.meanAbs = meanAbs;
            this.rmse = rmse;
        }

        static DiffStats compareU16LE(byte[] got, byte[] expected) {
            require(got.length == expected.length && (got.length & 1) == 0,
                    "u16 parity buffer length mismatch");
            int samples = got.length / 2;
            int differing = 0;
            int max = 0;
            long sumAbs = 0;
            double sumSq = 0.0;
            for (int i = 0; i < got.length; i += 2) {
                int g = (got[i] & 0xff) | ((got[i + 1] & 0xff) << 8);
                int e = (expected[i] & 0xff) | ((expected[i + 1] & 0xff) << 8);
                int d = Math.abs(g - e);
                if (d != 0) differing++;
                if (d > max) max = d;
                sumAbs += d;
                sumSq += (double) d * d;
            }
            return new DiffStats(differing, samples, max,
                    samples == 0 ? 0.0 : (double) sumAbs / samples,
                    samples == 0 ? 0.0 : Math.sqrt(sumSq / samples));
        }

        @Override
        public String toString() {
            return String.format(Locale.US,
                    "different=%d/%d maxAbs=%d meanAbs=%.9f rmse=%.9f",
                    differingSamples, samples, maxAbs, meanAbs, rmse);
        }
    }
}
