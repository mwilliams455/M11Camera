package com.m11.diagnostic;

import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;

/** Executes the explicitly selected, gated real-Xiaomi unpack+AHD hash probe. */
public final class M11RealRawProbe {
    private M11RealRawProbe() {}

    public static String run(Context context, Uri uri) throws Exception {
        HashResult source = hashSource(context, uri);
        String nativeResult;
        try (ParcelFileDescriptor pfd = context.getContentResolver().openFileDescriptor(uri, "r")) {
            if (pfd == null) throw new IllegalStateException("content provider returned null file descriptor");
            nativeResult = M11RealRawProbeBridge.probeRealXiaomiFd(pfd.getFd());
        }

        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown";
        return String.format(Locale.US,
                "M11 APK1A real Xiaomi RAW probe\n" +
                "explicitPixelDecodeProbe=true\n" +
                "deviceAbi=%s\n" +
                "sourceBytes=%d\n" +
                "sourceSha256=%s\n" +
                "sameByteRawpyOracleCompared=false\n\n%s",
                abi, source.bytes, source.sha256, nativeResult);
    }

    private static HashResult hashSource(Context context, Uri uri) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long bytes = 0;
        try (InputStream in = context.getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("content provider returned null input stream");
            byte[] buffer = new byte[64 * 1024];
            for (int n; (n = in.read(buffer)) >= 0;) {
                if (n == 0) continue;
                digest.update(buffer, 0, n);
                bytes += n;
            }
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) hex.append(String.format(Locale.US, "%02x", b & 0xff));
        return new HashResult(bytes, hex.toString());
    }

    private static final class HashResult {
        final long bytes;
        final String sha256;

        HashResult(long bytes, String sha256) {
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }
}
