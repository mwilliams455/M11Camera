package com.m11.diagnostic;

import android.app.Activity;
import android.graphics.Bitmap;
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

/**
 * Research-only same-DNG A/B for the disputed XYZ-D50 -> Leica internal entry seam.
 *
 * Branch OLD is the frozen RENDER1H entry: provisional M11 reference basis followed
 * by the selected static firmware CC0. Branch DIRECT_K enters with the fixed firmware
 * PCS_TO_INTERNAL K matrix and replaces only CC0 with identity. All later native
 * renderer stages, RAW/AHD processing and firmware tables are identical.
 */
public final class M11InternalEntryAbWorkflow {
    private M11InternalEntryAbWorkflow() {}

    private static final int EXPECTED_ASSET_SIZE = 23150;

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
        if (!meta.sourceTransformReady()) {
            throw new IOException("required Xiaomi dual-illuminant DNG source tags are incomplete");
        }
        if (!iso.present()) {
            throw new IOException("DNG ISO is unavailable; exact CC1 band selection is required");
        }

        byte[] assetBytes = readAsset(activity, M11RenderWorkflow.ASSET_NAME);
        if (assetBytes.length != EXPECTED_ASSET_SIZE) {
            throw new IOException("embedded M11 asset size mismatch");
        }
        String assetFileHash = sha256(assetBytes);
        if (!M11RenderWorkflow.ASSET_SHA256.equals(assetFileHash)) {
            throw new IOException("embedded M11 asset SHA-256 mismatch");
        }
        M11ReferenceAssetLoader.Asset asset;
        try (InputStream tables = new java.io.ByteArrayInputStream(assetBytes)) {
            asset = M11ReferenceAssetLoader.load(tables, iso.iso);
        }
        if (asset.metadata.thirdSroActiveInPixelChain) {
            throw new IOException("third SRO unexpectedly active");
        }

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

        double[] oldPreCc0 = M11InternalEntryCore.multiply3x3(
                M11ReferenceBasisCore.xyzD50ToM11AReferenceWb(),
                source.cameraToXyzD50);
        double[] directCameraToInternal = M11InternalEntryCore.cameraToInternal(source.cameraToXyzD50);
        M11ReferenceRendererCore.Tables identityCc0Tables = M11InternalEntryCore.withIdentityCc0(asset.tables);
        M11InternalEntryCore.Comparison matrixComparison = M11InternalEntryCore.compareEffectiveEntries(
                source.cameraToXyzD50, oldPreCc0, asset.tables.cc0);

        String baseStem = "IMG_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) +
                "_M11_ENTRY_AB";

        JSONObject common = commonDiagnostics(
                sourceUri, sourceHash, meta, iso, orientation, asset, assetFileHash, source,
                oldPreCc0, directCameraToInternal, matrixComparison);

        M11RenderOutputWriter.Result oldSaved;
        JSONObject oldJson = new JSONObject(common.toString());
        oldJson.put("branch", "OLD");
        oldJson.put("entry", "provisional_M11_reference_basis_then_selected_static_CC0");
        oldJson.put("cameraToNativeInput", jsonArray(oldPreCc0));
        oldJson.put("cc0Mode", "selected_static_firmware_CC0");
        oldJson.put("cc0Matrix", jsonArray(asset.tables.cc0));
        M11RenderBridge.Result oldNative;
        try (ParcelFileDescriptor pfd = activity.getContentResolver().openFileDescriptor(sourceUri, "r")) {
            if (pfd == null) throw new IOException("content provider returned null OLD render descriptor");
            oldNative = M11RenderBridge.renderStandardFd(pfd.getFd(), oldPreCc0, asset.tables);
        }
        Bitmap oldBitmap = oldNative.bitmap;
        validateLibRawOrientationDimensions(oldBitmap, meta, orientation, "OLD");
        oldJson.put("native", parseNativeDiagnostics(oldNative.diagnostics));
        oldJson.put("outputWidth", oldBitmap.getWidth());
        oldJson.put("outputHeight", oldBitmap.getHeight());
        oldJson.put("identityCc0Bypass", false);
        oldJson.put("m11SensorColorSpecAppliedToXiaomi", false);
        oldJson.put("totalWorkflowMsAtSave", (System.nanoTime() - startedNs) / 1_000_000.0);
        try {
            oldSaved = M11RenderOutputWriter.save(
                    activity, oldBitmap, oldJson.toString(2) + "\n", baseStem + "_OLD");
        } finally {
            oldBitmap.recycle();
        }

        M11RenderOutputWriter.Result directSaved;
        JSONObject directJson = new JSONObject(common.toString());
        directJson.put("branch", "DIRECT_K");
        directJson.put("entry", "firmware_PCS_TO_INTERNAL_K_from_white_balanced_XYZ_D50");
        directJson.put("cameraToNativeInput", jsonArray(directCameraToInternal));
        directJson.put("cc0Mode", "identity_bypass_equivalent_to_useCc0_false");
        directJson.put("cc0Matrix", jsonArray(M11InternalEntryCore.IDENTITY_CC0));
        M11RenderBridge.Result directNative;
        try (ParcelFileDescriptor pfd = activity.getContentResolver().openFileDescriptor(sourceUri, "r")) {
            if (pfd == null) throw new IOException("content provider returned null DIRECT_K render descriptor");
            directNative = M11RenderBridge.renderStandardFd(
                    pfd.getFd(), directCameraToInternal, identityCc0Tables);
        }
        Bitmap directBitmap = directNative.bitmap;
        validateLibRawOrientationDimensions(directBitmap, meta, orientation, "DIRECT_K");
        directJson.put("native", parseNativeDiagnostics(directNative.diagnostics));
        directJson.put("outputWidth", directBitmap.getWidth());
        directJson.put("outputHeight", directBitmap.getHeight());
        directJson.put("identityCc0Bypass", true);
        directJson.put("identityCc0ExactForPureMatrixStage", true);
        directJson.put("m11SensorColorSpecAppliedToXiaomi", false);
        directJson.put("totalWorkflowMsAtSave", (System.nanoTime() - startedNs) / 1_000_000.0);
        try {
            directSaved = M11RenderOutputWriter.save(
                    activity, directBitmap, directJson.toString(2) + "\n", baseStem + "_DIRECT_K");
        } finally {
            directBitmap.recycle();
        }

        return "M11 internal-entry same-DNG A/B complete\n" +
                "sourceSha256=" + sourceHash + "\n" +
                "ISO=" + iso.iso + " / CC1 band=" + asset.metadata.selectedCc1BandIndex + "\n" +
                String.format(Locale.US,
                        "matrixPrediction: old ~= %.12f * directK, directK relative = %+.9f EV, max residual = %.9f, RMS residual = %.9f\n",
                        matrixComparison.bestScalarOldToDirect,
                        matrixComparison.directRelativeEv,
                        matrixComparison.maxAbsResidualAfterScalar,
                        matrixComparison.rmsResidualAfterScalar) +
                "OLD PNG=" + oldSaved.png + "\n" +
                "OLD JPEG=" + oldSaved.jpeg + "\n" +
                "OLD JSON=" + oldSaved.diagnostics + "\n" +
                "DIRECT_K PNG=" + directSaved.png + "\n" +
                "DIRECT_K JPEG=" + directSaved.jpeg + "\n" +
                "DIRECT_K JSON=" + directSaved.diagnostics + "\n\n" +
                "Guardrail: native RENDER1H/JNI path is unchanged. DIRECT_K uses K * Xiaomi XYZ-D50 and an identity CC0 only to bypass the old static CC0 matrix; all downstream tables/stages are identical.";
    }

    private static JSONObject commonDiagnostics(
            Uri sourceUri,
            String sourceHash,
            DngMetadataReader.Metadata meta,
            DngIsoReader.Result iso,
            int orientation,
            M11ReferenceAssetLoader.Asset asset,
            String assetFileHash,
            M11SourceAdapterCore.Result source,
            double[] oldPreCc0,
            double[] directCameraToInternal,
            M11InternalEntryCore.Comparison comparison) throws Exception {
        JSONObject diagnostics = new JSONObject();
        diagnostics.put("schema", "m11camera.internal_entry_ab.device.v1");
        diagnostics.put("experiment", "same_DNG_old_entry_vs_firmware_direct_K");
        diagnostics.put("sourceUri", sourceUri.toString());
        diagnostics.put("sourceDngSha256", sourceHash);
        diagnostics.put("sourceMake", String.valueOf(meta.make));
        diagnostics.put("sourceModel", String.valueOf(meta.model));
        diagnostics.put("sourceUniqueCameraModel", String.valueOf(meta.uniqueCameraModel));
        diagnostics.put("sourceRawSize", meta.imageWidth + "x" + meta.imageHeight);
        diagnostics.put("dngOrientation", orientation);
        diagnostics.put("orientationHandledByLibRaw", true);
        diagnostics.put("javaOrientationApplied", false);
        diagnostics.put("orientationDimensionGate", true);
        diagnostics.put("iso", iso.iso);
        diagnostics.put("isoSource", iso.sourceName());
        diagnostics.put("cc1BandIndex", asset.metadata.selectedCc1BandIndex);
        M11ReferenceAssetLoader.IsoBand band = asset.metadata.cc1Bands[asset.metadata.selectedCc1BandIndex];
        diagnostics.put("cc1BandHalfOpen", jsonArray(band.lowerInclusive, band.upperExclusive));
        diagnostics.put("firmwareSourceSha256", asset.metadata.firmwareSha256);
        diagnostics.put("firmwareAssetSha256", assetFileHash);
        diagnostics.put("firmwareAssetPayloadSha256", asset.metadata.payloadSha256);
        diagnostics.put("sourceInterpolationFactor", source.interpolationFactor);
        diagnostics.put("referenceNeutral", jsonArray(source.referenceNeutral));
        diagnostics.put("cameraToXYZD50", jsonArray(source.cameraToXyzD50));
        diagnostics.put("oldCameraToM11ReferencePreCc0", jsonArray(oldPreCc0));
        diagnostics.put("oldEffectiveCameraToInternal", jsonArray(comparison.oldEffectiveCameraToInternal));
        diagnostics.put("directCameraToInternal", jsonArray(directCameraToInternal));
        diagnostics.put("firmwarePcsToInternalK", jsonArray(M11InternalEntryCore.PCS_TO_INTERNAL));
        JSONObject matrixPrediction = new JSONObject();
        matrixPrediction.put("bestScalarOldToDirect", comparison.bestScalarOldToDirect);
        matrixPrediction.put("directRelativeEv", comparison.directRelativeEv);
        matrixPrediction.put("maxAbsResidualAfterScalar", comparison.maxAbsResidualAfterScalar);
        matrixPrediction.put("rmsResidualAfterScalar", comparison.rmsResidualAfterScalar);
        diagnostics.put("matrixPrediction", matrixPrediction);
        diagnostics.put("mode", "Standard");
        diagnostics.put("sameDng", true);
        diagnostics.put("sameSourceAdapter", true);
        diagnostics.put("sameXyzD50Boundary", true);
        diagnostics.put("sameCc1ToneGammaCat42AndOutputMath", true);
        diagnostics.put("nativeRendererModifiedForExperiment", false);
        diagnostics.put("thirdSroApplied", false);
        diagnostics.put("hdr", false);
        diagnostics.put("localToneMapping", false);
        diagnostics.put("additionalDownstreamSourceWB", false);
        diagnostics.put("extraOutputOetf", false);
        diagnostics.put("promotionStatus", "diagnostic_only_not_promoted_to_RENDER1H");
        return diagnostics;
    }

    private static void validateLibRawOrientationDimensions(
            Bitmap bitmap, DngMetadataReader.Metadata meta, int orientation, String branch) throws IOException {
        boolean swapsAxes = orientation >= 5 && orientation <= 8;
        long expectedWidth = swapsAxes ? meta.imageHeight : meta.imageWidth;
        long expectedHeight = swapsAxes ? meta.imageWidth : meta.imageHeight;
        int actualWidth = bitmap.getWidth();
        int actualHeight = bitmap.getHeight();
        if (actualWidth != expectedWidth || actualHeight != expectedHeight) {
            bitmap.recycle();
            throw new IOException(branch + ": LibRaw-oriented bitmap dimensions mismatch: got " +
                    actualWidth + "x" + actualHeight + " expected " +
                    expectedWidth + "x" + expectedHeight + " for TIFF orientation " + orientation);
        }
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

    private static JSONArray jsonArray(double[] values) throws Exception {
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
