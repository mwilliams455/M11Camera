package com.m11.diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.FileInputStream;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Locale;

/** APK1A research shell: inspect a DNG and validate the source-calibration boundary. */
public final class MainActivity extends Activity {
    private static final int REQUEST_OPEN_DNG = 1101;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Leica M11 Diagnostic — APK1A");
        title.setTextSize(22f);
        body.addView(title);

        TextView scope = new TextView(this);
        scope.setText("Offline DNG research renderer foundation. Capture integration is intentionally deferred until controlled-render parity is stable.\n\n" +
                M11MatrixCore.thirdTargetSummary() + "\n\n" +
                "Third-matrix consumer placement: UNRESOLVED / not hard-wired.\n" +
                "CC1 selection: exact firmware ISO bands only; no nearest-band guessing.");
        body.addView(scope);

        Button open = new Button(this);
        open.setText("Select Xiaomi DNG");
        open.setOnClickListener(v -> chooseDng());
        body.addView(open);

        status = new TextView(this);
        status.setText("No DNG selected. Metadata/source-transform/ISO-band validation is ready.");
        status.setTextIsSelectable(true);
        body.addView(status);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        setContentView(scroll);
    }

    private void chooseDng() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                "image/x-adobe-dng", "image/dng", "application/octet-stream"
        });
        startActivityForResult(intent, REQUEST_OPEN_DNG);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_OPEN_DNG || resultCode != RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;
        int flags = data.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION;
        try {
            if (flags != 0) getContentResolver().takePersistableUriPermission(uri, flags);
        } catch (SecurityException ignored) {
            // Some providers grant temporary access only; sufficient for this session.
        }
        status.setText("Reading DNG metadata…");
        new Thread(() -> inspectDng(uri), "m11-dng-inspect").start();
    }

    private void inspectDng(Uri uri) {
        String result;
        try {
            StringBuilder s = new StringBuilder(describeDocument(uri));
            try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "r")) {
                if (pfd == null) throw new IllegalStateException("content provider returned null file descriptor");
                try (FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
                     FileChannel channel = in.getChannel()) {
                    DngMetadataReader.Metadata meta = DngMetadataReader.read(channel);
                    DngIsoReader.Result iso = DngIsoReader.read(channel);
                    s.append("\n\nDNG source metadata\n")
                            .append("make=").append(meta.make).append('\n')
                            .append("model=").append(meta.model).append('\n')
                            .append("uniqueCameraModel=").append(meta.uniqueCameraModel).append('\n')
                            .append("imageSize=").append(meta.imageWidth).append('x').append(meta.imageHeight).append('\n')
                            .append("blackLevel=").append(Arrays.toString(meta.blackLevel)).append('\n')
                            .append("whiteLevel=").append(Arrays.toString(meta.whiteLevel)).append('\n')
                            .append("CFARepeatPatternDim=").append(Arrays.toString(meta.cfaRepeatPatternDim)).append('\n')
                            .append("CFAPattern=").append(Arrays.toString(meta.cfaPattern)).append('\n')
                            .append("CalibrationIlluminant1=").append(meta.calibrationIlluminant1).append('\n')
                            .append("CalibrationIlluminant2=").append(meta.calibrationIlluminant2).append('\n')
                            .append("AsShotNeutral=").append(Arrays.toString(meta.asShotNeutral)).append('\n')
                            .append("CameraCalibration1DefaultedIdentity=")
                            .append(meta.cameraCalibration1DefaultedIdentity).append('\n')
                            .append("CameraCalibration2DefaultedIdentity=")
                            .append(meta.cameraCalibration2DefaultedIdentity).append('\n')
                            .append("sourceTransformReady=").append(meta.sourceTransformReady()).append('\n')
                            .append("iso=").append(iso.present() ? iso.iso : "unavailable").append('\n')
                            .append("isoSource=").append(iso.sourceName()).append('\n')
                            .append("firmwareCc1Band=").append(cc1BandSummary(iso));

                    if (meta.sourceTransformReady()) {
                        M11SourceAdapterCore.Result transform = M11SourceAdapterCore.buildDualIlluminantTransform(
                                meta.calibrationIlluminant1,
                                meta.calibrationIlluminant2,
                                meta.effectiveCalibration1(),
                                meta.effectiveCalibration2(),
                                meta.colorMatrix1,
                                meta.colorMatrix2,
                                meta.forwardMatrix1,
                                meta.forwardMatrix2,
                                meta.asShotNeutral);
                        s.append("\n\nAndroid source-transform result\n")
                                .append(String.format(Locale.US, "interpolationFactor=%.14f\n", transform.interpolationFactor))
                                .append("referenceNeutral=").append(Arrays.toString(transform.referenceNeutral)).append('\n')
                                .append("cameraToXYZD50=").append(formatMatrix(transform.cameraToXyzD50)).append('\n')
                                .append("additionalDownstreamSourceWB=false\n")
                                .append("interchangeSpace=linear scene-referred XYZ D50");
                    } else {
                        s.append("\n\nRequired dual-illuminant source tags are incomplete; no transform computed.");
                    }
                }
            }
            s.append("\n\nRAW decode/demosaic is intentionally not enabled yet: Android parity with the current LibRaw/AHD oracle must be proven first.");
            result = s.toString();
        } catch (Exception e) {
            result = "DNG inspection failed\n" + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        final String text = result;
        runOnUiThread(() -> status.setText(text));
    }

    private static String cc1BandSummary(DngIsoReader.Result iso) {
        if (!iso.present()) return "unresolved (ISO evidence unavailable)";
        int value = iso.iso;
        if (value < 10000) return "band0 [0,10000)";
        if (value < 20000) return "band1 [10000,20000)";
        if (value < 40000) return "band2 [20000,40000)";
        if (value < 200000) return "band3 [40000,200000)";
        return "unresolved (outside extracted firmware intervals)";
    }

    private String describeDocument(Uri uri) {
        String name = "unknown";
        long size = -1;
        try (Cursor c = getContentResolver().query(uri,
                new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int si = c.getColumnIndex(OpenableColumns.SIZE);
                if (ni >= 0) name = c.getString(ni);
                if (si >= 0 && !c.isNull(si)) size = c.getLong(si);
            }
        }
        return String.format(Locale.US, "Selected DNG candidate\nname=%s\nsize=%d bytes\nuri=%s", name, size, uri);
    }

    private static String formatMatrix(double[] m) {
        if (m == null || m.length != 9) return Arrays.toString(m);
        return String.format(Locale.US,
                "[[%.9f, %.9f, %.9f], [%.9f, %.9f, %.9f], [%.9f, %.9f, %.9f]]",
                m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]);
    }
}
