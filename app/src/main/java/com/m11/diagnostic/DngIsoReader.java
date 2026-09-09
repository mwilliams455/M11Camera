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

/**
 * Minimal classic-TIFF/Exif ISO reader for firmware Category-13 CC1 selection.
 *
 * DNG's primary IFD does not have to contain PhotographicSensitivity directly;
 * ordinary files usually point to an ExifIFD (tag 34665). This reader follows
 * the normal IFD chain, SubIFDs and ExifIFD pointers without interpreting image
 * payloads. It deliberately returns no guessed ISO when no supported evidence
 * is present or when high-ISO extended tags disagree.
 */
public final class DngIsoReader {
    private DngIsoReader() {}

    private static final int MAX_IFDS = 32;
    private static final int MAX_ENTRIES = 4096;

    private static final int TAG_SUB_IFDS = 330;
    private static final int TAG_EXIF_IFD = 34665;
    private static final int TAG_PHOTOGRAPHIC_SENSITIVITY = 34855;
    private static final int TAG_SENSITIVITY_TYPE = 34864;
    private static final int TAG_STANDARD_OUTPUT_SENSITIVITY = 34865;
    private static final int TAG_RECOMMENDED_EXPOSURE_INDEX = 34866;
    private static final int TAG_ISO_SPEED = 34867;
    private static final int SOURCE_AMBIGUOUS_HIGH_ISO = -2;

    public static final class Result {
        public final int iso;
        public final int sourceTag;

        Result(int iso, int sourceTag) {
            this.iso = iso;
            this.sourceTag = sourceTag;
        }

        public boolean present() {
            return iso > 0;
        }

        public String sourceName() {
            return switch (sourceTag) {
                case TAG_PHOTOGRAPHIC_SENSITIVITY -> "PhotographicSensitivity";
                case TAG_STANDARD_OUTPUT_SENSITIVITY -> "StandardOutputSensitivity";
                case TAG_RECOMMENDED_EXPOSURE_INDEX -> "RecommendedExposureIndex";
                case TAG_ISO_SPEED -> "ISOSpeed";
                case SOURCE_AMBIGUOUS_HIGH_ISO -> "high-ISO sensitivity tags ambiguous/unresolved";
                default -> "none";
            };
        }
    }

    private static final class Candidate {
        int photographic = -1;
        int sensitivityType = -1;
        int standard = -1;
        int recommended = -1;
        int isoSpeed = -1;

        Result result() {
            if (photographic > 0 && photographic < 65535) {
                return new Result(photographic, TAG_PHOTOGRAPHIC_SENSITIVITY);
            }
            if (photographic == 65535) {
                Result extended = resolveExtended();
                if (extended != null) return extended;
                return new Result(-1, SOURCE_AMBIGUOUS_HIGH_ISO);
            }
            Result extended = resolveExtended();
            return extended != null ? extended : new Result(-1, -1);
        }

        private Result resolveExtended() {
            List<Result> values = new ArrayList<>();
            addIfSelected(values, 1, 4, 5, 7, standard, TAG_STANDARD_OUTPUT_SENSITIVITY);
            addIfSelected(values, 2, 4, 6, 7, recommended, TAG_RECOMMENDED_EXPOSURE_INDEX);
            addIfSelected(values, 3, 5, 6, 7, isoSpeed, TAG_ISO_SPEED);

            if (sensitivityType <= 0 || sensitivityType > 7) {
                values.clear();
                if (standard > 0) values.add(new Result(standard, TAG_STANDARD_OUTPUT_SENSITIVITY));
                if (recommended > 0) values.add(new Result(recommended, TAG_RECOMMENDED_EXPOSURE_INDEX));
                if (isoSpeed > 0) values.add(new Result(isoSpeed, TAG_ISO_SPEED));
            }
            if (values.isEmpty()) return null;
            int value = values.get(0).iso;
            for (Result r : values) if (r.iso != value) return null;
            return values.get(0);
        }

        private void addIfSelected(List<Result> out, int a, int b, int c, int d,
                                   int value, int tag) {
            if ((sensitivityType == a || sensitivityType == b || sensitivityType == c || sensitivityType == d)
                    && value > 0) {
                out.add(new Result(value, tag));
            }
        }
    }

    public static Result read(FileChannel channel) throws IOException {
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
            if (magic == 43) throw new IOException("BigTIFF DNG is not supported by APK1A ISO reader");
            throw new IOException("classic TIFF magic 42 required");
        }
        long firstIfd = h.getInt() & 0xffffffffL;
        Candidate candidate = new Candidate();
        parseIfd(channel, order, firstIfd, new HashSet<>(), new int[] {0}, candidate);
        return candidate.result();
    }

    private static void parseIfd(FileChannel ch, ByteOrder order, long offset,
                                 Set<Long> seen, int[] count, Candidate candidate) throws IOException {
        while (offset != 0 && count[0] < MAX_IFDS && seen.add(offset)) {
            count[0]++;
            int entries = ByteBuffer.wrap(readAt(ch, offset, 2)).order(order).getShort() & 0xffff;
            if (entries > MAX_ENTRIES) throw new IOException("IFD entry count too large: " + entries);

            long[] nested = new long[MAX_ENTRIES + 1];
            int nestedCount = 0;
            for (int i = 0; i < entries; i++) {
                long p = offset + 2L + 12L * i;
                byte[] raw = readAt(ch, p, 12);
                ByteBuffer e = ByteBuffer.wrap(raw).order(order);
                int tag = e.getShort() & 0xffff;
                int type = e.getShort() & 0xffff;
                long valueCount = e.getInt() & 0xffffffffL;

                if (tag == TAG_PHOTOGRAPHIC_SENSITIVITY || tag == TAG_SENSITIVITY_TYPE ||
                        tag == TAG_STANDARD_OUTPUT_SENSITIVITY || tag == TAG_RECOMMENDED_EXPOSURE_INDEX ||
                        tag == TAG_ISO_SPEED) {
                    int value = firstPositiveInteger(ch, order, raw, type, valueCount);
                    if (value > 0) {
                        if (tag == TAG_PHOTOGRAPHIC_SENSITIVITY && candidate.photographic < 0) candidate.photographic = value;
                        else if (tag == TAG_SENSITIVITY_TYPE && candidate.sensitivityType < 0) candidate.sensitivityType = value;
                        else if (tag == TAG_STANDARD_OUTPUT_SENSITIVITY && candidate.standard < 0) candidate.standard = value;
                        else if (tag == TAG_RECOMMENDED_EXPOSURE_INDEX && candidate.recommended < 0) candidate.recommended = value;
                        else if (tag == TAG_ISO_SPEED && candidate.isoSpeed < 0) candidate.isoSpeed = value;
                    }
                } else if (tag == TAG_EXIF_IFD) {
                    long nestedOffset = firstOffset(ch, order, raw, type, valueCount);
                    if (nestedOffset != 0 && nestedCount < nested.length) nested[nestedCount++] = nestedOffset;
                } else if (tag == TAG_SUB_IFDS) {
                    long[] offsets = offsets(ch, order, raw, type, valueCount);
                    for (long nestedOffset : offsets) {
                        if (nestedOffset != 0 && nestedCount < nested.length) nested[nestedCount++] = nestedOffset;
                    }
                }
            }

            for (int i = 0; i < nestedCount; i++) {
                parseIfd(ch, order, nested[i], seen, count, candidate);
            }
            long nextPos = offset + 2L + 12L * entries;
            offset = u32(readAt(ch, nextPos, 4), order);
        }
    }

    private static int firstPositiveInteger(FileChannel ch, ByteOrder order, byte[] raw,
                                            int type, long count) throws IOException {
        if (count < 1) return -1;
        int size = typeSize(type);
        if (size == 0) return -1;
        byte[] data = valueBytes(ch, order, raw, size, count);
        if (data.length < size) return -1;
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        long value;
        switch (type) {
            case 1: value = b.get() & 0xffL; break;
            case 3: value = b.getShort() & 0xffffL; break;
            case 4: value = b.getInt() & 0xffffffffL; break;
            case 5: {
                long num = b.getInt() & 0xffffffffL;
                long den = b.getInt() & 0xffffffffL;
                if (den == 0) return -1;
                value = Math.round((double) num / den);
                break;
            }
            default: return -1;
        }
        return value > 0 && value <= Integer.MAX_VALUE ? (int) value : -1;
    }

    private static long firstOffset(FileChannel ch, ByteOrder order, byte[] raw,
                                    int type, long count) throws IOException {
        long[] value = offsets(ch, order, raw, type, count);
        return value.length == 0 ? 0 : value[0];
    }

    private static long[] offsets(FileChannel ch, ByteOrder order, byte[] raw,
                                  int type, long count) throws IOException {
        if ((type != 3 && type != 4) || count < 1 || count > 1024) return new long[0];
        int size = typeSize(type);
        byte[] data = valueBytes(ch, order, raw, size, count);
        if (data.length < size * count) return new long[0];
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        long[] out = new long[(int) count];
        for (int i = 0; i < out.length; i++) {
            out[i] = type == 3 ? (b.getShort() & 0xffffL) : (b.getInt() & 0xffffffffL);
        }
        return out;
    }

    private static byte[] valueBytes(FileChannel ch, ByteOrder order, byte[] raw,
                                     int typeSize, long count) throws IOException {
        long byteCount = typeSize * count;
        if (byteCount <= 0 || byteCount > 8192 || byteCount > Integer.MAX_VALUE) return new byte[0];
        int bytes = (int) byteCount;
        if (bytes <= 4) {
            byte[] out = new byte[bytes];
            System.arraycopy(raw, 8, out, 0, bytes);
            return out;
        }
        long offset = ByteBuffer.wrap(raw, 8, 4).order(order).getInt() & 0xffffffffL;
        return readAt(ch, offset, bytes);
    }

    private static int typeSize(int type) {
        return switch (type) {
            case 1 -> 1;
            case 3 -> 2;
            case 4 -> 4;
            case 5 -> 8;
            default -> 0;
        };
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
