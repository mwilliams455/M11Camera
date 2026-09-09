package com.m11.diagnostic;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Minimal classic-TIFF/DNG metadata reader for the source-calibration boundary. */
public final class DngMetadataReader {
    private DngMetadataReader() {}

    private static final int MAX_IFDS = 32;
    private static final int MAX_ENTRIES = 4096;
    private static final long MAX_VALUE_BYTES = 16L * 1024L * 1024L;

    private static final int TAG_IMAGE_WIDTH = 256;
    private static final int TAG_IMAGE_LENGTH = 257;
    private static final int TAG_MAKE = 271;
    private static final int TAG_MODEL = 272;
    private static final int TAG_SUB_IFDS = 330;
    private static final int TAG_CFA_REPEAT_PATTERN_DIM = 33421;
    private static final int TAG_CFA_PATTERN = 33422;
    private static final int TAG_UNIQUE_CAMERA_MODEL = 50708;
    private static final int TAG_BLACK_LEVEL = 50714;
    private static final int TAG_WHITE_LEVEL = 50717;
    private static final int TAG_COLOR_MATRIX1 = 50721;
    private static final int TAG_COLOR_MATRIX2 = 50722;
    private static final int TAG_CAMERA_CALIBRATION1 = 50723;
    private static final int TAG_CAMERA_CALIBRATION2 = 50724;
    private static final int TAG_AS_SHOT_NEUTRAL = 50728;
    private static final int TAG_CALIBRATION_ILLUMINANT1 = 50778;
    private static final int TAG_CALIBRATION_ILLUMINANT2 = 50779;
    private static final int TAG_FORWARD_MATRIX1 = 50964;
    private static final int TAG_FORWARD_MATRIX2 = 50965;

    public static final class Metadata {
        public String make;
        public String model;
        public String uniqueCameraModel;
        public long imageWidth;
        public long imageHeight;
        public double[] blackLevel;
        public double[] whiteLevel;
        public long[] cfaRepeatPatternDim;
        public long[] cfaPattern;
        public double[] colorMatrix1;
        public double[] colorMatrix2;
        public double[] cameraCalibration1;
        public double[] cameraCalibration2;
        public boolean cameraCalibration1DefaultedIdentity;
        public boolean cameraCalibration2DefaultedIdentity;
        public double[] asShotNeutral;
        public int calibrationIlluminant1 = -1;
        public int calibrationIlluminant2 = -1;
        public double[] forwardMatrix1;
        public double[] forwardMatrix2;

        public boolean sourceTransformReady() {
            return matrix9(colorMatrix1) && matrix9(colorMatrix2)
                    && matrix9(forwardMatrix1) && matrix9(forwardMatrix2)
                    && vector3(asShotNeutral)
                    && calibrationIlluminant1 >= 0 && calibrationIlluminant2 >= 0;
        }

        public double[] effectiveCalibration1() {
            return matrix9(cameraCalibration1) ? cameraCalibration1.clone() : identity3();
        }

        public double[] effectiveCalibration2() {
            return matrix9(cameraCalibration2) ? cameraCalibration2.clone() : identity3();
        }

        private static boolean matrix9(double[] v) { return v != null && v.length == 9; }
        private static boolean vector3(double[] v) { return v != null && v.length == 3; }
        private static double[] identity3() {
            return new double[] {1,0,0, 0,1,0, 0,0,1};
        }
    }

    private static final class Entry {
        final int type;
        final long count;
        final byte[] data;
        final ByteOrder order;

        Entry(int type, long count, byte[] data, ByteOrder order) {
            this.type = type;
            this.count = count;
            this.data = data;
            this.order = order;
        }

        String ascii() {
            int n = 0;
            while (n < data.length && data[n] != 0) n++;
            return new String(data, 0, n, java.nio.charset.StandardCharsets.US_ASCII).trim();
        }

        long[] integers() throws IOException {
            if (count > Integer.MAX_VALUE) throw new IOException("TIFF value count too large");
            int n = (int) count;
            long[] out = new long[n];
            ByteBuffer b = ByteBuffer.wrap(data).order(order);
            for (int i = 0; i < n; i++) {
                switch (type) {
                    case 1: case 6: case 7: out[i] = b.get() & 0xffL; break;
                    case 3: out[i] = b.getShort() & 0xffffL; break;
                    case 4: out[i] = b.getInt() & 0xffffffffL; break;
                    case 8: out[i] = b.getShort(); break;
                    case 9: out[i] = b.getInt(); break;
                    default: throw new IOException("TIFF type " + type + " is not an integer type");
                }
            }
            return out;
        }

        double[] numbers() throws IOException {
            if (count > Integer.MAX_VALUE) throw new IOException("TIFF value count too large");
            int n = (int) count;
            double[] out = new double[n];
            ByteBuffer b = ByteBuffer.wrap(data).order(order);
            for (int i = 0; i < n; i++) {
                switch (type) {
                    case 1: case 6: case 7: out[i] = b.get() & 0xff; break;
                    case 3: out[i] = b.getShort() & 0xffff; break;
                    case 4: out[i] = b.getInt() & 0xffffffffL; break;
                    case 5: {
                        long num = b.getInt() & 0xffffffffL;
                        long den = b.getInt() & 0xffffffffL;
                        out[i] = den == 0 ? Double.NaN : (double) num / den;
                        break;
                    }
                    case 8: out[i] = b.getShort(); break;
                    case 9: out[i] = b.getInt(); break;
                    case 10: {
                        int num = b.getInt();
                        int den = b.getInt();
                        out[i] = den == 0 ? Double.NaN : (double) num / den;
                        break;
                    }
                    case 11: out[i] = b.getFloat(); break;
                    case 12: out[i] = b.getDouble(); break;
                    default: throw new IOException("unsupported numeric TIFF type " + type);
                }
            }
            return out;
        }
    }

    public static Metadata read(FileChannel channel) throws IOException {
        if (channel == null) throw new IllegalArgumentException("channel == null");
        byte[] header = readAt(channel, 0, 8);
        ByteOrder order;
        if (header[0] == 'I' && header[1] == 'I') order = ByteOrder.LITTLE_ENDIAN;
        else if (header[0] == 'M' && header[1] == 'M') order = ByteOrder.BIG_ENDIAN;
        else throw new IOException("not a TIFF/DNG byte order marker");
        ByteBuffer h = ByteBuffer.wrap(header).order(order);
        h.position(2);
        int magic = h.getShort() & 0xffff;
        if (magic != 42) {
            if (magic == 43) throw new IOException("BigTIFF DNG is not supported by APK1A metadata reader");
            throw new IOException("classic TIFF magic 42 required");
        }
        long firstIfd = h.getInt() & 0xffffffffL;
        Metadata out = new Metadata();
        parseChain(channel, order, firstIfd, new HashSet<>(), out, new int[] {0});
        out.cameraCalibration1DefaultedIdentity = out.cameraCalibration1 == null;
        out.cameraCalibration2DefaultedIdentity = out.cameraCalibration2 == null;
        return out;
    }

    private static void parseChain(FileChannel ch, ByteOrder order, long offset,
                                   Set<Long> seen, Metadata out, int[] count) throws IOException {
        while (offset != 0 && count[0] < MAX_IFDS && seen.add(offset)) {
            count[0]++;
            int n = ByteBuffer.wrap(readAt(ch, offset, 2)).order(order).getShort() & 0xffff;
            if (n > MAX_ENTRIES) throw new IOException("IFD entry count too large: " + n);
            List<Long> subIfds = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                long p = offset + 2L + 12L * i;
                byte[] raw = readAt(ch, p, 12);
                ByteBuffer e = ByteBuffer.wrap(raw).order(order);
                int tag = e.getShort() & 0xffff;
                int type = e.getShort() & 0xffff;
                long valueCount = e.getInt() & 0xffffffffL;
                Entry value = readEntry(ch, order, raw, e, type, valueCount);
                if (value == null) continue;

                switch (tag) {
                    case TAG_IMAGE_WIDTH:
                        if (out.imageWidth == 0) out.imageWidth = firstLong(value, 0);
                        break;
                    case TAG_IMAGE_LENGTH:
                        if (out.imageHeight == 0) out.imageHeight = firstLong(value, 0);
                        break;
                    case TAG_MAKE:
                        if (out.make == null && type == 2) out.make = value.ascii();
                        break;
                    case TAG_MODEL:
                        if (out.model == null && type == 2) out.model = value.ascii();
                        break;
                    case TAG_UNIQUE_CAMERA_MODEL:
                        if (out.uniqueCameraModel == null && type == 2) out.uniqueCameraModel = value.ascii();
                        break;
                    case TAG_BLACK_LEVEL:
                        if (out.blackLevel == null) out.blackLevel = value.numbers();
                        break;
                    case TAG_WHITE_LEVEL:
                        if (out.whiteLevel == null) out.whiteLevel = value.numbers();
                        break;
                    case TAG_CFA_REPEAT_PATTERN_DIM:
                        if (out.cfaRepeatPatternDim == null) out.cfaRepeatPatternDim = value.integers();
                        break;
                    case TAG_CFA_PATTERN:
                        if (out.cfaPattern == null) out.cfaPattern = value.integers();
                        break;
                    case TAG_COLOR_MATRIX1:
                        if (out.colorMatrix1 == null) out.colorMatrix1 = requireCount(value.numbers(), 9, "ColorMatrix1");
                        break;
                    case TAG_COLOR_MATRIX2:
                        if (out.colorMatrix2 == null) out.colorMatrix2 = requireCount(value.numbers(), 9, "ColorMatrix2");
                        break;
                    case TAG_CAMERA_CALIBRATION1:
                        if (out.cameraCalibration1 == null) out.cameraCalibration1 = requireCount(value.numbers(), 9, "CameraCalibration1");
                        break;
                    case TAG_CAMERA_CALIBRATION2:
                        if (out.cameraCalibration2 == null) out.cameraCalibration2 = requireCount(value.numbers(), 9, "CameraCalibration2");
                        break;
                    case TAG_AS_SHOT_NEUTRAL:
                        if (out.asShotNeutral == null) out.asShotNeutral = requireCount(value.numbers(), 3, "AsShotNeutral");
                        break;
                    case TAG_CALIBRATION_ILLUMINANT1:
                        if (out.calibrationIlluminant1 < 0) out.calibrationIlluminant1 = (int) firstLong(value, -1);
                        break;
                    case TAG_CALIBRATION_ILLUMINANT2:
                        if (out.calibrationIlluminant2 < 0) out.calibrationIlluminant2 = (int) firstLong(value, -1);
                        break;
                    case TAG_FORWARD_MATRIX1:
                        if (out.forwardMatrix1 == null) out.forwardMatrix1 = requireCount(value.numbers(), 9, "ForwardMatrix1");
                        break;
                    case TAG_FORWARD_MATRIX2:
                        if (out.forwardMatrix2 == null) out.forwardMatrix2 = requireCount(value.numbers(), 9, "ForwardMatrix2");
                        break;
                    case TAG_SUB_IFDS:
                        for (long sub : value.integers()) if (sub != 0) subIfds.add(sub);
                        break;
                    default:
                        break;
                }
            }
            for (long sub : subIfds) parseChain(ch, order, sub, seen, out, count);
            long nextPos = offset + 2L + 12L * n;
            offset = u32(readAt(ch, nextPos, 4), order);
        }
    }

    private static Entry readEntry(FileChannel ch, ByteOrder order, byte[] raw, ByteBuffer e,
                                   int type, long count) throws IOException {
        int size = typeSize(type);
        if (size == 0 || count > Integer.MAX_VALUE) return null;
        long bytesLong = count * (long) size;
        if (bytesLong < 0 || bytesLong > MAX_VALUE_BYTES) return null;
        int bytes = (int) bytesLong;
        byte[] data;
        if (bytes <= 4) {
            data = new byte[bytes];
            System.arraycopy(raw, 8, data, 0, bytes);
        } else {
            long valueOffset = e.getInt() & 0xffffffffL;
            data = readAt(ch, valueOffset, bytes);
        }
        return new Entry(type, count, data, order);
    }

    private static long firstLong(Entry e, long fallback) throws IOException {
        long[] v = e.integers();
        return v.length == 0 ? fallback : v[0];
    }

    private static double[] requireCount(double[] value, int count, String name) throws IOException {
        if (value.length != count) throw new IOException(name + " expected " + count + " values, got " + value.length);
        for (double v : value) if (!Double.isFinite(v)) throw new IOException(name + " contains non-finite values");
        return value;
    }

    private static int typeSize(int type) {
        switch (type) {
            case 1: case 2: case 6: case 7: return 1;
            case 3: case 8: return 2;
            case 4: case 9: case 11: return 4;
            case 5: case 10: case 12: return 8;
            default: return 0;
        }
    }

    private static byte[] readAt(FileChannel ch, long offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + (long) length > ch.size()) {
            throw new EOFException("TIFF read outside file: offset=" + offset + " length=" + length);
        }
        ByteBuffer b = ByteBuffer.allocate(length);
        long p = offset;
        while (b.hasRemaining()) {
            int n = ch.read(b, p);
            if (n < 0) throw new EOFException("unexpected EOF");
            if (n == 0) continue;
            p += n;
        }
        return b.array();
    }

    private static long u32(byte[] bytes, ByteOrder order) {
        return ByteBuffer.wrap(bytes).order(order).getInt() & 0xffffffffL;
    }
}
