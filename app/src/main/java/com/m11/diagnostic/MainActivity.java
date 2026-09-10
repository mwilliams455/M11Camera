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

/** APK1A research shell: inspect a DNG and validate controlled renderer boundaries. */
public final class MainActivity extends Activity {
    private static final int REQUEST_IDENTIFY_DNG = 1101;
    private static final int REQUEST_REAL_RAW_PROBE = 1102;
    private static final int REQUEST_REAL_RAW_EXPORT_SOURCE = 1103;
    private static final int REQUEST_REAL_RAW_EXPORT_DEST = 1104;
    private static final int REQUEST_RENDER_M11_STANDARD = 1105;

    private TextView status;
    private Uri pendingExportSource;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Leica M11 Diagnostic — RENDER1A");
        title.setTextSize(22f);
        body.addView(title);

        TextView scope = new TextView(this);
        scope.setText("Offline DNG research renderer foundation. Capture integration remains deferred until controlled rendering is photographically validated.\n\n" +
                M11MatrixCore.thirdTargetSummary() + "\n\n" +
                "Third-matrix consumer placement: UNRESOLVED / inactive.\n" +
                "CC1 selection: exact firmware ISO bands only; no nearest-band guessing.\n" +
                "Original identify/probe/export paths remain available and isolated.\n" +
                "RENDER1A Standard: canonical M11-P 2.6.1 table asset + frozen Xiaomi RAW/AHD path + explicit Xiaomi source calibration/reference-basis bridge.\n" +
                "No HDR, no local tone mapping, no second source WB, no extra output OETF.\n" +
                "The known highlight-range/Category42 consumer question is NOT corrected by eye in this baseline build.");
        body.addView(scope);

        Button selfTest = new Button(this);
        selfTest.setText("Run bundled ARM RAW parity self-test");
        selfTest.setOnClickListener(v -> runSyntheticRawSelfTest());
        body.addView(selfTest);

        Button identify = new Button(this);
        identify.setText("Select Xiaomi DNG — identify only");
        identify.setOnClickListener(v -> chooseDng(REQUEST_IDENTIFY_DNG));
        body.addView(identify);

        Button realProbe = new Button(this);
        realProbe.setText("Select Xiaomi DNG — gated unpack + AHD hash test");
        realProbe.setOnClickListener(v -> chooseDng(REQUEST_REAL_RAW_PROBE));
        body.addView(realProbe);

        Button realExport = new Button(this);
        realExport.setText("Select Xiaomi DNG — export gated AHD parity .gz");
        realExport.setOnClickListener(v -> chooseDng(REQUEST_REAL_RAW_EXPORT_SOURCE));
        body.addView(realExport);

        Button render = new Button(this);
        render.setText("Select Xiaomi DNG — render M11 Standard");
        render.setOnClickListener(v -> chooseDng(REQUEST_RENDER_M11_STANDARD));
        body.addView(render);

        status = new TextView(this);
        status.setText("Ready. RENDER1A Standard is available as a separate, provenance-gated action; REALRAW1C and diagnostic paths are preserved.");
        status.setTextIsSelectable(true);
        body.addView(status);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        setContentView(scroll);
    }

    private void runSyntheticRawSelfTest() {
        status.setText("Running bundled 32x32 synthetic RAW through pinned LibRaw unpack + AHD on this device…");
        new Thread(() -> {
            String result;
            try {
                result = M11SyntheticRawSelfTest.run(this);
            } catch (Throwable t) {
                result = "Bundled RAW parity self-test FAILED\n" +
                        t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()) + "\n\n" +
                        "No real/user DNG was decoded. The original DNG path remains identify-only.";
            }
            final String text = result;
            runOnUiThread(() -> status.setText(text));
        }, "m11-synthetic-raw-selftest").start();
    }

    private void chooseDng(int requestCode) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                "image/x-adobe-dng", "image/dng", "application/octet-stream"
        });
        startActivityForResult(intent, requestCode);
    }

    private void chooseExportDestination() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/gzip");
        intent.putExtra(Intent.EXTRA_TITLE, "M11_REALRAW1C_AHD_u16le.bin.gz");
        startActivityForResult(intent, REQUEST_REAL_RAW_EXPORT_DEST);
    }

    private void persistPermission(Intent data, Uri uri) {
        int flags = data.getFlags() &
                (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        try {
            if (flags != 0) getContentResolver().takePersistableUriPermission(uri, flags);
        } catch (SecurityException ignored) {
            // Some providers grant temporary access only; sufficient for this session.
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;

        if (requestCode == REQUEST_REAL_RAW_EXPORT_DEST) {
            persistPermission(data, uri);
            final Uri source = pendingExportSource;
            pendingExportSource = null;
            if (source == null) {
                status.setText("REALRAW1C export cancelled: source DNG state was lost.");
                return;
            }
            status.setText("Running gated real Xiaomi AHD and gzip-exporting the derived 16-bit RGB buffer…");
            new Thread(() -> runRealRawAhdExport(source, uri), "m11-realraw-ahd-export").start();
            return;
        }

        if (requestCode != REQUEST_IDENTIFY_DNG &&
                requestCode != REQUEST_REAL_RAW_PROBE &&
                requestCode != REQUEST_REAL_RAW_EXPORT_SOURCE &&
                requestCode != REQUEST_RENDER_M11_STANDARD) return;

        persistPermission(data, uri);

        if (requestCode == REQUEST_IDENTIFY_DNG) {
            status.setText("Reading Java DNG metadata and native LibRaw identification only…");
            new Thread(() -> inspectDng(uri), "m11-dng-inspect").start();
        } else if (requestCode == REQUEST_REAL_RAW_PROBE) {
            status.setText("Running explicitly selected real Xiaomi DNG through gated LibRaw unpack + AHD hash probe…");
            new Thread(() -> runRealRawProbe(uri), "m11-realraw-probe").start();
        } else if (requestCode == REQUEST_REAL_RAW_EXPORT_SOURCE) {
            pendingExportSource = uri;
            status.setText("Source DNG selected. Choose where to save the private REALRAW1C AHD gzip export.");
            chooseExportDestination();
        } else {
            status.setText("Rendering M11 Standard from the exact canonical firmware asset. Baseline math is frozen; no highlight workaround is being applied…");
            new Thread(() -> runM11StandardRender(uri), "m11-render1a-standard").start();
        }
    }

    private void runM11StandardRender(Uri uri) {
        String result;
        try {
            result = describeDocument(uri) + "\n\n" + M11RenderWorkflow.run(this, uri);
        } catch (Throwable t) {
            result = "M11 RENDER1A Standard FAILED\n" +
                    t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()) + "\n\n" +
                    "The render path is fail-closed: exact firmware asset, ISO band, Xiaomi RAW identity and source metadata must all pass before output is saved.";
        }
        final String text = result;
        runOnUiThread(() -> status.setText(text));
    }

    private void runRealRawProbe(Uri uri) {
        String result;
        try {
            result = describeDocument(uri) + "\n\n" + M11RealRawProbe.run(this, uri);
        } catch (Throwable t) {
            result = "Real Xiaomi RAW probe FAILED\n" +
                    t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()) + "\n\n" +
                    "The native gate refuses non-matching inputs. M11 renderer was not invoked.";
        }
        final String text = result;
        runOnUiThread(() -> status.setText(text));
    }

    private void runRealRawAhdExport(Uri sourceUri, Uri outputUri) {
        String result;
        try {
            result = describeDocument(sourceUri) + "\n\n" +
                    M11RealRawAhdExport.run(this, sourceUri, outputUri) + "\n\n" +
                    "Upload the saved .gz file privately for exact ARM/x86 AHD comparison.\n" +
                    "This export contains derived AHD pixels only; the M11 renderer was not invoked.";
        } catch (Throwable t) {
            result = "REALRAW1C AHD export FAILED\n" +
                    t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()) + "\n\n" +
                    "The native gate refuses non-matching inputs. M11 renderer was not invoked.";
        }
        final String text = result;
        runOnUiThread(() -> status.setText(text));
    }

    private void inspectDng(Uri uri) {
        String result;
        try {
            StringBuilder s = new StringBuilder(describeDocument(uri));
            try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "r")) {
                if (pfd == null) throw new IllegalStateException("content provider returned null file descriptor");
                String nativeIdentify = M11NativeRawBridge.identifyFd(pfd.getFd());
                s.append("\n\nNative LibRaw open/identify — independent metadata view\n").append(nativeIdentify);

                try (FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
                     FileChannel channel = in.getChannel()) {
                    DngMetadataReader.Metadata meta = DngMetadataReader.read(channel);
                    DngIsoReader.Result iso = DngIsoReader.read(channel);
                    s.append("\n\nJava TIFF/DNG metadata — independent metadata view\n")
                            .append("make=").append(meta.make).append('\n')
                            .append("model=").append(meta.model).append('\n')
                            .append("uniqueCameraModel=").append(meta.uniqueCameraModel).append('\n')
                            .append("imageSize=").append(meta.imageWidth).append('x').append(meta.imageHeight).append('\n')
                            .append("orientation=").append(M11DngOrientation.read(channel)).append('\n')
                            .append("blackLevel=").append(Arrays.toString(meta.blackLevel)).append('\n')
                            .append("whiteLevel=").append(Arrays.toString(meta.whiteLevel)).append('\n')
                            .append("CFARepeatPatternDim=").append(Arrays.toString(meta.cfaRepeatPatternDim)).append('\n')
                            .append("CFAPattern=").append(Arrays.toString(meta.cfaPattern)).append('\n')
                            .append("CalibrationIlluminant1=").append(meta.calibrationIlluminant1).append('\n')
                            .append("CalibrationIlluminant2=").append(meta.calibrationIlluminant2).append('\n')
                            .append("AsShotNeutral=").append(Arrays.toString(meta.asShotNeutral)).append('\n')
                            .append("CameraCalibration1DefaultedIdentity=").append(meta.cameraCalibration1DefaultedIdentity).append('\n')
                            .append("CameraCalibration2DefaultedIdentity=").append(meta.cameraCalibration2DefaultedIdentity).append('\n')
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
            s.append("\n\nOriginal user-DNG identify boundary status\n")
                    .append("LibRaw open/identify: ENABLED for diagnostics only.\n")
                    .append("RAW unpack: DISABLED in this identify path.\n")
                    .append("AHD demosaic: DISABLED in this identify path.\n")
                    .append("M11 renderer hookup: available only through the separate explicit RENDER1A Standard action.\n")
                    .append("REALRAW1C probe/export remains isolated from renderer invocation.");
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
        if (value <= 200000) return "band3 [40000,200001)";
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
