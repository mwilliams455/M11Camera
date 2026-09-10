package com.m11.diagnostic;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** End-to-end controlled Xiaomi DNG -> firmware-gated M11 Standard RENDER1A action. */
public final class M11RenderWorkflow {
    private M11RenderWorkflow() {}

    public static final String ASSET_NAME = "m11_reference_tables_v1.bin";
    public static final String ASSET_SHA256 = "54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219";
    private static final int ASSET_SIZE = 23150;

    public static String run(Activity activity, Uri sourceUri) throws Exception {
        long startedNs = System.nanoTime();
        String sourceHash = sha256(activity, sourceUri);

        DngMetadataReader.Metadata meta;
        DngIsoReader.Result iso;
        int orientation;
        try (ParcelFileDescriptor pfd = activity.getContentResolver().openFileDescriptor(sourceUri, "r")) {
            if (pfd == null) throw new IOException("content provider returned null metadata descriptor");
            try (FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
                 FileChannel channel = in.getChannel()) {
                meta = DngMetadataReader.read(channel);
                iso = DngIsoReader.read(channel);
                orientation = M11DngOrientation.read(channel);
            }
        }
        if (!meta.sourceTransformReady()) throw new IOException("required Xiaomi dual-illuminant DNG source tags are incomplete");
        if (!iso.present()) throw new IOException("DNG ISO is unavailable; exact CC1 band selection is required");

        byte[] assetBytes = readAsset(activity, ASSET_NAME);
        if (assetBytes.length != ASSET_SIZE) throw new IOException("embedded M11 asset size mismatch");
        String assetFileHash = sha256(assetBytes);
        if (!ASSET_SHA256.equals(assetFileHash)) throw new IOException("embedded M11 asset SHA-256 mismatch");
        M11ReferenceAssetLoader.Asset asset;
        try (InputStream tables = new java.io.ByteArrayInputStream(assetBytes)) {
            asset = M11ReferenceAssetLoader.load(tables, iso.iso);
        }
        if (asset.metadata.thirdSroActiveInPixelChain) throw new IOException("third SRO unexpectedly active");

        M11SourceAdapterCore.Result source = M11SourceAdapterCore.buildDualIlluminantTransform(
                meta.calibrationIlluminant1,
                meta.calibrationIlluminant2,
                meta.effectiveCalibration1(),
                meta.effectiveCalibration2(),
                meta.colorMatrix1,
                meta.colorMatrix2,
                meta.forwardMatrix1,
                meta.forwardMatrix2,
                meta.asShotNeutral);
        double[] cameraToM11 = multiply3x3(
                M11ReferenceBasisCore.xyzD50ToM11AReferenceWb(), source.cameraToXyzD50);

        M11RenderBridge.Result nativeResult;
        try (ParcelFileDescriptor pfd = activity.getContentResolver().openFileDescriptor(sourceUri, "r")) {
            if (pfd == null) throw new IOException("content provider returned null render descriptor");
            nativeResult = M11RenderBridge.renderStandardFd(pfd.getFd(), cameraToM11, asset.tables);
        }

        Bitmap rawBitmap = nativeResult.bitmap;
        Bitmap oriented = applyOrientation(rawBitmap, orientation);
        if (oriented != rawBitmap) rawBitmap.recycle();

        String stem = "IMG_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + "_M11_STANDARD";
        JSONObject diagnostics = new JSONObject();
        diagnostics.put("schema", "m11camera.render1a.device.v1");
        diagnostics.put("sourceUri", sourceUri.toString());
        diagnostics.put("sourceDngSha256", sourceHash);
        diagnostics.put("sourceMake", String.valueOf(meta.make));
        diagnostics.put("sourceModel", String.valueOf(meta.model));
        diagnostics.put("sourceUniqueCameraModel", String.valueOf(meta.uniqueCameraModel));
        diagnostics.put("sourceRawSize", meta.imageWidth + "x" + meta.imageHeight);
        diagnostics.put("dngOrientation", orientation);
        diagnostics.put("iso", iso.iso);
        diagnostics.put("isoSource", iso.sourceName());
        diagnostics.put("cc1BandIndex", asset.metadata.selectedCc1BandIndex);
        M11ReferenceAssetLoader.IsoBand band = asset.metadata.cc1Bands[asset.metadata.selectedCc1BandIndex];
        diagnostics.put("cc1BandHalfOpen", jsonArray(band.lowerInclusive, band.upperExclusive));
        diagnostics.put("firmwareSourceSha256", asset.metadata.firmwareSha256);
        diagnostics.put("firmwareAssetSha256", assetFileHash);
        diagnostics.put("firmwareAssetPayloadSha256", asset.metadata.payloadSha256);
        JSONObject sourceHashes = new JSONObject();
        for (java.util.Map.Entry<String, String> e : asset.metadata.canonicalSourceSha256.entrySet()) {
            sourceHashes.put(e.getKey(), e.getValue());
        }
        diagnostics.put("canonicalSourceSha256", sourceHashes);
        diagnostics.put("sourceInterpolationFactor", source.interpolationFactor);
        diagnostics.put("referenceNeutral", jsonArray(source.referenceNeutral));
        diagnostics.put("cameraToXYZD50", jsonArray(source.cameraToXyzD50));
        diagnostics.put("cameraToM11Reference", jsonArray(cameraToM11));
        diagnostics.put("mode", "Standard");
        diagnostics.put("thirdSroApplied", false);
        diagnostics.put("hdr", false);
        diagnostics.put("localToneMapping", false);
        diagnostics.put("additionalDownstreamSourceWB", false);
        diagnostics.put("extraOutputOetf", false);
        diagnostics.put("rendererMathChangedForHighlightIssue", false);
        diagnostics.put("knownResearchBoundary", "Category42 full 44-byte consumer and highlight-range/clamp placement remain under firmware investigation");
        diagnostics.put("native", parseNativeDiagnostics(nativeResult.diagnostics));
        diagnostics.put("outputWidth", oriented.getWidth());
        diagnostics.put("outputHeight", oriented.getHeight());
        diagnostics.put("outputPixelFormat", "RGBA_8888 -> PNG/JPEG");
        diagnostics.put("jpegQuality", 98);
        diagnostics.put("totalWorkflowMs", (System.nanoTime() - startedNs) / 1_000_000.0);

        String json = diagnostics.toString(2) + "\n";
        M11RenderOutputWriter.Result saved;
        try {
            saved = M11RenderOutputWriter.save(activity, oriented, json, stem);
        } finally {
            oriented.recycle();
        }

        return "M11 RENDER1A Standard complete\n" +
                "sourceSha256=" + sourceHash + "\n" +
                "ISO=" + iso.iso + " / CC1 band=" + asset.metadata.selectedCc1BandIndex +
                " [" + band.lowerInclusive + "," + band.upperExclusive + ")\n" +
                "firmwareAssetSha256=" + assetFileHash + "\n" +
                String.format(Locale.US, "sourceInterpolationFactor=%.14f\n", source.interpolationFactor) +
                "orientation=" + orientation + " -> " + diagnostics.getInt("outputWidth") + "x" + diagnostics.getInt("outputHeight") + "\n" +
                "PNG=" + saved.png + "\n" +
                "JPEG=" + saved.jpeg + "\n" +
                "JSON=" + saved.diagnostics + "\n\n" +
                "Baseline renderer preserved: no HDR, no local tone mapping, no extra WB/OETF, third SRO inactive, no highlight workaround.";
    }

    private static JSONArray jsonArray(double[] values) {
        JSONArray out = new JSONArray();
        for (double value : values) out.put(value);
        return out;
    }

    private static JSONArray jsonArray(long a, long b) {
        JSONArray out = new JSONArray();
        out.put(a);
        out.put(b);
        return out;
    }

    private static JSONObject parseNativeDiagnostics(String text) throws Exception {
        JSONObject obj = new JSONObject();
        if (text == null) return obj;
        for (String line : text.split("\\n")) {
            int p = line.indexOf('=');
            if (p <= 0) continue;
            obj.put(line.substring(0, p), line.substring(p + 1));
        }
        return obj;
    }

    private static Bitmap applyOrientation(Bitmap source, int orientation) {
        if (orientation == 1) return source;
        Matrix matrix = new Matrix();
        switch (orientation) {
            case 2: matrix.setScale(-1f, 1f); break;
            case 3: matrix.setRotate(180f); break;
            case 4: matrix.setScale(1f, -1f); break;
            case 5: matrix.setRotate(90f); matrix.postScale(-1f, 1f); break;
            case 6: matrix.setRotate(90f); break;
            case 7: matrix.setRotate(-90f); matrix.postScale(-1f, 1f); break;
            case 8: matrix.setRotate(-90f); break;
            default: throw new IllegalArgumentException("unsupported TIFF orientation " + orientation);
        }
        return Bitmap.createBitmap(source, 0, 0, source.getWidth(), source.getHeight(), matrix, false);
    }

    private static double[] multiply3x3(double[] a, double[] b) {
        if (a == null || b == null || a.length != 9 || b.length != 9) throw new IllegalArgumentException("3x3 matrices required");
        double[] out = new double[9];
        for (int r = 0; r < 3; r++) {
            for (int c = 0; c < 3; c++) {
                out[r * 3 + c] = a[r * 3] * b[c] + a[r * 3 + 1] * b[3 + c] + a[r * 3 + 2] * b[6 + c];
            }
        }
        return out;
    }

    private static byte[] readAsset(Activity activity, String name) throws IOException {
        try (InputStream in = activity.getAssets().open(name)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) >= 0) if (n > 0) out.write(buffer, 0, n);
            return out.toByteArray();
        }
    }

    private static String sha256(Activity activity, Uri uri) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = activity.getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IOException("source DNG input stream unavailable");
            byte[] buffer = new byte[1024 * 1024];
            int n;
            while ((n = in.read(buffer)) >= 0) if (n > 0) digest.update(buffer, 0, n);
        }
        return hex(digest.digest());
    }

    private static String sha256(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format(Locale.US, "%02x", b & 0xff));
        return out.toString();
    }
}
