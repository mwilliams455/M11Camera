package com.m11.diagnostic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loader for the compact, hash-gated M11 APK1A firmware-derived table asset.
 *
 * The production asset is created only by tools/package_m11_apk_assets.py after
 * that tool has verified the exact canonical M11-P 2.6.1 extraction hashes.
 * This loader verifies the serialization checksum and the declared primary
 * source hashes, selects the genuine Category-13 ISO band, and materializes the
 * existing M11ReferenceRendererCore.Tables contract without changing renderer
 * mathematics.
 *
 * The 33-word SRO block is retained as provenance/audit data.  Its third matrix
 * is deliberately not returned as an active pixel transform; the format itself
 * carries an explicit zero placement flag until the firmware consumer is known.
 */
public final class M11ReferenceAssetLoader {
    private M11ReferenceAssetLoader() {}

    private static final byte[] MAGIC = new byte[] {'M','1','1','A','P','K','1','A'};
    private static final int FORMAT_VERSION = 1;
    public static final String EXPECTED_FIRMWARE_SHA256 =
            "0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83";

    private static final String[] SOURCE_NAMES = {
            "category3_CC0_candidate.json",
            "category13_CC1_candidate.json",
            "tone_q12_reconstructed_curves.csv",
            "gamma_4096_high_nibble_first.csv",
            "category24_YCC.json",
            "category42_saturation.json",
            "sro_colour_management.json"
    };
    private static final String[] EXPECTED_SOURCE_SHA256 = {
            "b3948532d23bf22c22e45d751fc2cc902c86055337a45c5a8bcb12e5202c970e",
            "7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb",
            "b142a9cfcf51e52849e5aac17c224b4de113c79a8ae809b47d8f9fd5fbef658b",
            "0738ae474494fc83299bd75ba7a4b298950fed49005b6c5693eb0f18c23cfbdc",
            "6d67e6b601683477e6322d0097d8b2afcc6e015416f93152ec25e8e8ff2fe5f8",
            "5869a69073a698f506b86c068261d0640b90e93da20627d9d7a7926b043c46cb",
            "1bd82548e7d64e3151f59bf05458d4216faa5c0f314d8668442eb692e43b576a"
    };

    private static final int[] EXPECTED_YCC = {77,150,29,-43,-85,128,128,-107,-21};
    private static final int[] EXPECTED_TONE_LUMA = {77,149,29};
    private static final int[] EXPECTED_THIRD_SRO = {212,-165,-71,-73,676,85,-27,174,285};
    private static final int[][] EXPECTED_MODE_RECORDS = {
            {0, -1, -1, 511, 100},
            {1,  0,  0, 588, 115},
            {2,  1,  1, 665, 130}
    };

    public static final class IsoBand {
        public final long lowerInclusive;
        public final long upperExclusive;
        public final int[] matrixQ9;

        IsoBand(long lowerInclusive, long upperExclusive, int[] matrixQ9) {
            this.lowerInclusive = lowerInclusive;
            this.upperExclusive = upperExclusive;
            this.matrixQ9 = matrixQ9.clone();
        }
    }

    public static final class Metadata {
        public final int formatVersion;
        public final String firmwareSha256;
        public final Map<String, String> canonicalSourceSha256;
        public final String payloadSha256;
        public final int requestedIso;
        public final int selectedCc1BandIndex;
        public final IsoBand[] cc1Bands;
        public final int[] sroWords;
        public final boolean thirdSroActiveInPixelChain;

        Metadata(int formatVersion, String firmwareSha256, Map<String, String> canonicalSourceSha256,
                 String payloadSha256, int requestedIso, int selectedCc1BandIndex,
                 IsoBand[] cc1Bands, int[] sroWords, boolean thirdSroActiveInPixelChain) {
            this.formatVersion = formatVersion;
            this.firmwareSha256 = firmwareSha256;
            this.canonicalSourceSha256 = Collections.unmodifiableMap(new LinkedHashMap<>(canonicalSourceSha256));
            this.payloadSha256 = payloadSha256;
            this.requestedIso = requestedIso;
            this.selectedCc1BandIndex = selectedCc1BandIndex;
            this.cc1Bands = cc1Bands.clone();
            this.sroWords = sroWords.clone();
            this.thirdSroActiveInPixelChain = thirdSroActiveInPixelChain;
        }
    }

    public static final class Asset {
        public final Metadata metadata;
        public final M11ReferenceRendererCore.Tables tables;

        Asset(Metadata metadata, M11ReferenceRendererCore.Tables tables) {
            this.metadata = metadata;
            this.tables = tables;
        }
    }

    public static Asset load(InputStream input, int iso) throws IOException {
        if (input == null) throw new IllegalArgumentException("input == null");
        if (iso < 0) throw new IllegalArgumentException("ISO must be non-negative");

        byte[] all = readAll(input);
        if (all.length < MAGIC.length + 4 + 32 + 32) throw new IOException("M11 asset is truncated");
        int payloadLength = all.length - 32;
        byte[] payload = Arrays.copyOf(all, payloadLength);
        byte[] trailer = Arrays.copyOfRange(all, payloadLength, all.length);
        byte[] actualDigest = sha256(payload);
        if (!MessageDigest.isEqual(trailer, actualDigest)) throw new IOException("M11 asset payload SHA-256 mismatch");

        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IOException("M11 asset magic mismatch");
        int version = in.readInt();
        if (version != FORMAT_VERSION) throw new IOException("unsupported M11 asset format version " + version);

        String firmwareHash = readHash(in);
        if (!EXPECTED_FIRMWARE_SHA256.equals(firmwareHash)) throw new IOException("unexpected M11 firmware source hash");
        Map<String, String> sourceHashes = new LinkedHashMap<>();
        for (int i = 0; i < SOURCE_NAMES.length; i++) {
            String digest = readHash(in);
            sourceHashes.put(SOURCE_NAMES[i], digest);
            if (!EXPECTED_SOURCE_SHA256[i].equals(digest)) {
                throw new IOException("unexpected canonical source hash for " + SOURCE_NAMES[i]);
            }
        }

        int ccQ = in.readUnsignedShort();
        int toneQ = in.readUnsignedShort();
        int yccQ = in.readUnsignedShort();
        int gammaMax = in.readUnsignedShort();
        int toneSamples = in.readUnsignedShort();
        int gammaSamples = in.readUnsignedShort();
        int bandCount = in.readUnsignedShort();
        int modeCount = in.readUnsignedShort();
        if (ccQ != 512 || toneQ != 4096 || yccQ != 256 || gammaMax != 1023 ||
                toneSamples != 1024 || gammaSamples != 4096 || bandCount != 4 || modeCount != 3) {
            throw new IOException("M11 asset fixed-point/cardinality contract mismatch");
        }

        int[] cc0Q9 = readI16(in, 9);
        IsoBand[] bands = new IsoBand[bandCount];
        int selected = -1;
        for (int i = 0; i < bandCount; i++) {
            long lower = Integer.toUnsignedLong(in.readInt());
            long upper = Integer.toUnsignedLong(in.readInt());
            int[] matrix = readI16(in, 9);
            if (upper <= lower) throw new IOException("invalid CC1 ISO band interval at index " + i);
            bands[i] = new IsoBand(lower, upper, matrix);
            if (lower <= iso && iso < upper) selected = i;
        }
        if (selected < 0) throw new IOException("ISO " + iso + " does not match a canonical CC1 band");

        int[] ycc = readI16(in, 9);
        if (!Arrays.equals(ycc, EXPECTED_YCC)) throw new IOException("Category24 YCC invariant mismatch");
        int[] toneLuma = new int[] {in.readUnsignedShort(), in.readUnsignedShort(), in.readUnsignedShort()};
        if (!Arrays.equals(toneLuma, EXPECTED_TONE_LUMA)) throw new IOException("tone luma invariant mismatch");

        double[] toneX = new double[toneSamples];
        double[][] toneCurves = new double[7][toneSamples];
        for (int i = 0; i < toneSamples; i++) toneX[i] = i / (double)(toneSamples - 1);
        for (int state = 0; state < 7; state++) {
            for (int i = 0; i < toneSamples; i++) {
                int gain = in.readUnsignedShort();
                toneCurves[state][i] = toneX[i] * gain / (double)toneQ;
                if (state == 0 && gain != 4096) throw new IOException("tone -3 identity invariant mismatch at " + i);
            }
        }

        double[] gammaX = new double[gammaSamples];
        double[] gammaY = new double[gammaSamples];
        for (int i = 0; i < gammaSamples; i++) {
            gammaX[i] = i / (double)(gammaSamples - 1);
            int value = in.readUnsignedShort();
            if (value > gammaMax) throw new IOException("gamma value exceeds 10-bit range at " + i);
            gammaY[i] = value / (double)gammaMax;
        }

        for (int i = 0; i < modeCount; i++) {
            int modeId = in.readUnsignedByte();
            int contrast = in.readByte();
            int saturationState = in.readByte();
            int reserved = in.readUnsignedByte();
            int satField = in.readUnsignedShort();
            int chromaPercent = in.readUnsignedShort();
            int[] expected = EXPECTED_MODE_RECORDS[i];
            if (reserved != 0 || modeId != expected[0] || contrast != expected[1] ||
                    saturationState != expected[2] || satField != expected[3] || chromaPercent != expected[4]) {
                throw new IOException("creative-mode mapping mismatch at record " + i);
            }
        }

        int[] sroWords = new int[33];
        for (int i = 0; i < sroWords.length; i++) sroWords[i] = in.readInt();
        for (int i = 0; i < EXPECTED_THIRD_SRO.length; i++) {
            if (sroWords[22 + i] != EXPECTED_THIRD_SRO[i]) throw new IOException("corrected third SRO invariant mismatch");
        }
        if (sroWords[31] != 0 || sroWords[32] != 6807) throw new IOException("third SRO metadata mismatch");
        int thirdSroActive = in.readUnsignedByte();
        if (in.readUnsignedByte() != 0 || in.readUnsignedByte() != 0 || in.readUnsignedByte() != 0) {
            throw new IOException("non-zero reserved bytes after SRO placement flag");
        }
        if (thirdSroActive != 0) throw new IOException("third SRO consumer placement is unresolved and must remain inactive");
        if (in.available() != 0) throw new IOException("unexpected trailing bytes inside M11 asset payload");

        double[] cc0 = q9ToDouble(cc0Q9);
        double[] cc1 = q9ToDouble(bands[selected].matrixQ9);
        M11ReferenceRendererCore.Tables tables = new M11ReferenceRendererCore.Tables(
                cc0, cc1, toneX, toneCurves, gammaX, gammaY);
        Metadata metadata = new Metadata(version, firmwareHash, sourceHashes, toHex(actualDigest),
                iso, selected, bands, sroWords, false);
        return new Asset(metadata, tables);
    }

    private static int[] readI16(DataInputStream in, int count) throws IOException {
        int[] out = new int[count];
        for (int i = 0; i < count; i++) out[i] = in.readShort();
        return out;
    }

    private static double[] q9ToDouble(int[] q9) {
        double[] out = new double[q9.length];
        for (int i = 0; i < q9.length; i++) out[i] = q9[i] / 512.0;
        return out;
    }

    private static String readHash(DataInputStream in) throws IOException {
        byte[] bytes = new byte[32];
        in.readFully(bytes);
        return toHex(bytes);
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = input.read(buf)) >= 0) {
            if (n > 0) out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static byte[] sha256(byte[] data) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
