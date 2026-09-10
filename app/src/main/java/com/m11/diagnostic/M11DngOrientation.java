package com.m11.diagnostic;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;

/** Minimal classic-TIFF Orientation (tag 274) reader for output presentation only. */
public final class M11DngOrientation {
    private M11DngOrientation() {}

    private static final int TAG_ORIENTATION = 274;

    public static int read(FileChannel channel) throws IOException {
        byte[] header = readAt(channel, 0, 8);
        ByteOrder order;
        if (header[0] == 'I' && header[1] == 'I') order = ByteOrder.LITTLE_ENDIAN;
        else if (header[0] == 'M' && header[1] == 'M') order = ByteOrder.BIG_ENDIAN;
        else throw new IOException("not a TIFF/DNG byte order marker");
        ByteBuffer h = ByteBuffer.wrap(header).order(order);
        h.position(2);
        if ((h.getShort() & 0xffff) != 42) throw new IOException("classic TIFF orientation reader requires magic 42");
        long ifd = h.getInt() & 0xffffffffL;
        if (ifd == 0) return 1;
        int count = ByteBuffer.wrap(readAt(channel, ifd, 2)).order(order).getShort() & 0xffff;
        if (count > 4096) throw new IOException("orientation IFD entry count too large");
        for (int i = 0; i < count; i++) {
            byte[] raw = readAt(channel, ifd + 2L + i * 12L, 12);
            ByteBuffer e = ByteBuffer.wrap(raw).order(order);
            int tag = e.getShort() & 0xffff;
            int type = e.getShort() & 0xffff;
            long n = e.getInt() & 0xffffffffL;
            if (tag != TAG_ORIENTATION) continue;
            if (n != 1) throw new IOException("Orientation tag must contain one value");
            int value;
            if (type == 3) value = ByteBuffer.wrap(raw, 8, 2).order(order).getShort() & 0xffff;
            else if (type == 4) value = ByteBuffer.wrap(raw, 8, 4).order(order).getInt();
            else throw new IOException("unsupported Orientation TIFF type " + type);
            if (value < 1 || value > 8) throw new IOException("invalid TIFF Orientation " + value);
            return value;
        }
        return 1;
    }

    private static byte[] readAt(FileChannel channel, long offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + (long) length > channel.size()) {
            throw new EOFException("TIFF orientation read outside file");
        }
        ByteBuffer b = ByteBuffer.allocate(length);
        long p = offset;
        while (b.hasRemaining()) {
            int n = channel.read(b, p);
            if (n < 0) throw new EOFException("unexpected EOF");
            if (n == 0) continue;
            p += n;
        }
        return b.array();
    }
}
