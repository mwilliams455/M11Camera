package com.m11.diagnostic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.Test;

public final class DngIsoReaderTest {
    @Test
    public void followsLittleEndianExifIfdToPhotographicSensitivity() throws Exception {
        DngIsoReader.Result r = readFixture(ByteOrder.LITTLE_ENDIAN, false, 640);
        assertTrue(r.present());
        assertEquals(640, r.iso);
        assertEquals("PhotographicSensitivity", r.sourceName());
    }

    @Test
    public void followsBigEndianExifIfdToPhotographicSensitivity() throws Exception {
        DngIsoReader.Result r = readFixture(ByteOrder.BIG_ENDIAN, false, 12500);
        assertTrue(r.present());
        assertEquals(12500, r.iso);
        assertEquals("PhotographicSensitivity", r.sourceName());
    }

    @Test
    public void acceptsDirectPrimaryIfdIsoWithoutGuessing() throws Exception {
        DngIsoReader.Result r = readFixture(ByteOrder.LITTLE_ENDIAN, true, 3200);
        assertEquals(3200, r.iso);
        assertEquals("PhotographicSensitivity", r.sourceName());
    }

    @Test
    public void resolves65535SentinelUsingSelectedIsoSpeedTag() throws Exception {
        DngIsoReader.Result r = readHighIsoFixture(ByteOrder.LITTLE_ENDIAN, 3,
                -1, -1, 102400);
        assertTrue(r.present());
        assertEquals(102400, r.iso);
        assertEquals("ISOSpeed", r.sourceName());
    }

    @Test
    public void resolvesAllSelectedHighIsoTagsOnlyWhenTheyAgree() throws Exception {
        DngIsoReader.Result r = readHighIsoFixture(ByteOrder.BIG_ENDIAN, 7,
                102400, 102400, 102400);
        assertTrue(r.present());
        assertEquals(102400, r.iso);
        assertEquals("StandardOutputSensitivity", r.sourceName());
    }

    @Test
    public void rejectsDisagreeingHighIsoTagsInsteadOfGuessingCc1Band() throws Exception {
        DngIsoReader.Result r = readHighIsoFixture(ByteOrder.LITTLE_ENDIAN, 7,
                102400, 128000, 102400);
        assertFalse(r.present());
        assertEquals(-1, r.iso);
        assertTrue(r.sourceName().contains("ambiguous"));
    }

    @Test
    public void rejects65535SentinelWhenExtendedTagIsMissing() throws Exception {
        DngIsoReader.Result r = readHighIsoFixture(ByteOrder.LITTLE_ENDIAN, 3,
                -1, -1, -1);
        assertFalse(r.present());
        assertEquals(-1, r.iso);
        assertTrue(r.sourceName().contains("unresolved"));
    }

    @Test
    public void missingIsoReturnsExplicitNoEvidence() throws Exception {
        byte[] bytes = classicTiffHeader(ByteOrder.LITTLE_ENDIAN, 8, 32);
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        b.position(8);
        b.putShort((short) 0);
        b.putInt(0);
        DngIsoReader.Result r = read(bytes);
        assertFalse(r.present());
        assertEquals(-1, r.iso);
        assertEquals("none", r.sourceName());
    }

    private static DngIsoReader.Result readFixture(ByteOrder order, boolean direct, int iso) throws Exception {
        byte[] bytes = classicTiffHeader(order, 8, 128);
        ByteBuffer b = ByteBuffer.wrap(bytes).order(order);
        b.position(8);
        b.putShort((short) 1);
        if (direct) {
            putShortEntry(b, 34855, iso);
            b.putInt(0);
        } else {
            putLongEntry(b, 34665, 64);
            b.putInt(0);
            b.position(64);
            b.putShort((short) 1);
            putShortEntry(b, 34855, iso);
            b.putInt(0);
        }
        return read(bytes);
    }

    private static DngIsoReader.Result readHighIsoFixture(ByteOrder order, int sensitivityType,
                                                           int standard, int recommended,
                                                           int isoSpeed) throws Exception {
        byte[] bytes = classicTiffHeader(order, 8, 256);
        ByteBuffer b = ByteBuffer.wrap(bytes).order(order);
        b.position(8);
        b.putShort((short) 1);
        putLongEntry(b, 34665, 64);
        b.putInt(0);

        int entryCount = 2;
        if (standard > 0) entryCount++;
        if (recommended > 0) entryCount++;
        if (isoSpeed > 0) entryCount++;
        b.position(64);
        b.putShort((short) entryCount);
        putShortEntry(b, 34855, 65535);
        putShortEntry(b, 34864, sensitivityType);
        if (standard > 0) putLongEntry(b, 34865, standard);
        if (recommended > 0) putLongEntry(b, 34866, recommended);
        if (isoSpeed > 0) putLongEntry(b, 34867, isoSpeed);
        b.putInt(0);
        return read(bytes);
    }

    private static byte[] classicTiffHeader(ByteOrder order, int firstIfd, int size) {
        ByteBuffer b = ByteBuffer.allocate(size).order(order);
        if (order == ByteOrder.LITTLE_ENDIAN) {
            b.put((byte) 'I').put((byte) 'I');
        } else {
            b.put((byte) 'M').put((byte) 'M');
        }
        b.putShort((short) 42);
        b.putInt(firstIfd);
        return b.array();
    }

    private static void putLongEntry(ByteBuffer b, int tag, long value) {
        b.putShort((short) tag);
        b.putShort((short) 4);
        b.putInt(1);
        b.putInt((int) value);
    }

    private static void putShortEntry(ByteBuffer b, int tag, int value) {
        b.putShort((short) tag);
        b.putShort((short) 3);
        b.putInt(1);
        b.putShort((short) value);
        b.putShort((short) 0);
    }

    private static DngIsoReader.Result read(byte[] bytes) throws Exception {
        Path path = Files.createTempFile("m11-dng-iso-", ".tif");
        try {
            Files.write(path, bytes);
            try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
                return DngIsoReader.read(ch);
            }
        } finally {
            Files.deleteIfExists(path);
        }
    }
}
