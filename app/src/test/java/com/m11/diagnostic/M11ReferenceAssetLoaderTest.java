package com.m11.diagnostic;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import org.junit.Test;

public class M11ReferenceAssetLoaderTest {
    private static final String[] HASHES = {
            "0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83",
            "b3948532d23bf22c22e45d751fc2cc902c86055337a45c5a8bcb12e5202c970e",
            "7301628d67ef66e6f10e76825ddf451e28644e8dd1ce324bd35447af5b01aecb",
            "b142a9cfcf51e52849e5aac17c224b4de113c79a8ae809b47d8f9fd5fbef658b",
            "0738ae474494fc83299bd75ba7a4b298950fed49005b6c5693eb0f18c23cfbdc",
            "6d67e6b601683477e6322d0097d8b2afcc6e015416f93152ec25e8e8ff2fe5f8",
            "59ffbdefdc608285d31b437e7d3c9187e77a894c0a79efa07e521f62c7ddcd54",
            "1bd82548e7d64e3151f59bf05458d4216faa5c0f314d8668442eb692e43b576a"
    };
    private static final int[][] CC1 = {
            {1041,-372,-157,-117,630,-1,-4,-78,595},
            {910,-290,-108,-74,561,25,22,-41,531},
            {806,-225,-69,-39,506,45,44,-12,480},
            {715,-169,-34,-9,458,63,61,15,436}
    };
    private static final int[][] ISO = {{0,10000},{10000,20000},{20000,40000},{40000,200001}};
    private static final int[] SRO = {
            2358,-546,-66,-2488,6300,1785,-403,797,3504,12,2850,
            1700,-326,-200,-2354,5409,974,-612,976,2276,12,6807,
            212,-165,-71,-73,676,85,-27,174,285,0,6807
    };

    @Test public void loadsBandOneAndMaterializesImplicitAxes() throws Exception {
        M11ReferenceAssetLoader.Asset asset = M11ReferenceAssetLoader.load(new ByteArrayInputStream(fixture(false)), 15000);
        assertEquals(1, asset.metadata.selectedCc1BandIndex);
        assertEquals(20000L, asset.metadata.cc1Bands[1].upperExclusive);
        assertFalse(asset.metadata.thirdSroActiveInPixelChain);
        assertArrayEquals(SRO, asset.metadata.sroWords);
        assertEquals(910.0 / 512.0, asset.tables.cc1[0], 0.0);
        assertEquals(1024, asset.tables.toneX.length);
        assertEquals(4096, asset.tables.gammaX.length);
    }

    @Test public void firmwareInclusiveUpperEndpointIso200000SelectsLastBand() throws Exception {
        M11ReferenceAssetLoader.Asset asset = M11ReferenceAssetLoader.load(new ByteArrayInputStream(fixture(false)), 200000);
        assertEquals(3, asset.metadata.selectedCc1BandIndex);
        assertEquals(200001L, asset.metadata.cc1Bands[3].upperExclusive);
    }

    @Test public void rejectsIsoOutsideExtractedFirmwareEvidence() throws Exception {
        try {
            M11ReferenceAssetLoader.load(new ByteArrayInputStream(fixture(false)), 200001);
            fail("ISO above inclusive firmware upper bound must be rejected");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("does not match"));
        }
    }

    @Test public void rejectsTamperedPayload() throws Exception {
        byte[] bytes = fixture(false);
        bytes[400] ^= 1;
        try {
            M11ReferenceAssetLoader.load(new ByteArrayInputStream(bytes), 100);
            fail("tampered payload should fail");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("SHA-256"));
        }
    }

    @Test public void rejectsAttemptToActivateUnresolvedThirdSro() throws Exception {
        try {
            M11ReferenceAssetLoader.load(new ByteArrayInputStream(fixture(true)), 100);
            fail("third SRO must remain inactive");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("third SRO"));
        }
    }

    private static byte[] fixture(boolean activateThirdSro) throws Exception {
        ByteArrayOutputStream payloadBytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(payloadBytes);
        out.write(new byte[] {'M','1','1','A','P','K','1','A'});
        out.writeInt(1);
        for (String h : HASHES) out.write(hex(h));
        out.writeShort(512); out.writeShort(4096); out.writeShort(256); out.writeShort(1023);
        out.writeShort(1024); out.writeShort(4096); out.writeShort(4); out.writeShort(3);
        writeI16(out, new int[] {495,-58,63,10,601,-111,49,-255,705});
        for (int i = 0; i < 4; i++) {
            out.writeInt(ISO[i][0]); out.writeInt(ISO[i][1]); writeI16(out, CC1[i]);
        }
        writeI16(out, new int[] {77,150,29,-43,-85,128,128,-107,-21});
        out.writeShort(77); out.writeShort(149); out.writeShort(29);
        for (int state = 0; state < 7; state++) for (int i = 0; i < 1024; i++) out.writeShort(4096);
        for (int i = 0; i < 4096; i++) out.writeShort((int)Math.round(i * 1023.0 / 4095.0));
        int[][] modes = {{0,-1,-1,511,100},{1,0,0,588,115},{2,1,1,665,130}};
        for (int[] mode : modes) {
            out.writeByte(mode[0]); out.writeByte(mode[1]); out.writeByte(mode[2]); out.writeByte(0);
            out.writeShort(mode[3]); out.writeShort(mode[4]);
        }
        for (int word : SRO) out.writeInt(word);
        out.writeByte(activateThirdSro ? 1 : 0); out.writeByte(0); out.writeByte(0); out.writeByte(0);
        out.flush();
        byte[] payload = payloadBytes.toByteArray();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        ByteArrayOutputStream asset = new ByteArrayOutputStream();
        asset.write(payload); asset.write(digest);
        return asset.toByteArray();
    }

    private static void writeI16(DataOutputStream out, int[] values) throws IOException {
        for (int value : values) out.writeShort(value);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte)Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
