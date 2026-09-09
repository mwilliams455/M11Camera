package com.m11.diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.Locale;

/** APK1A research shell: select a DNG and expose provenance before renderer porting. */
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
        scope.setText("Offline DNG research renderer shell. Capture integration is intentionally deferred until controlled-render parity is stable.\n\n" +
                M11MatrixCore.thirdTargetSummary() + "\n\n" +
                "Third-matrix consumer placement: UNRESOLVED / not hard-wired.");
        body.addView(scope);

        Button open = new Button(this);
        open.setText("Select Xiaomi DNG");
        open.setOnClickListener(v -> chooseDng());
        body.addView(open);

        status = new TextView(this);
        status.setText("No DNG selected. APK1A shell is ready for decoder/source-adapter porting.");
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
        final int flags = data.getFlags() &
                (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        try {
            getContentResolver().takePersistableUriPermission(uri, flags & Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException ignored) {
            // Some providers grant temporary access only; that is sufficient for APK1A.
        }
        status.setText(describe(uri));
    }

    private String describe(Uri uri) {
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
        } catch (RuntimeException e) {
            return "Selected URI: " + uri + "\nMetadata query failed: " + e;
        }
        return String.format(Locale.US,
                "Selected DNG candidate\nname=%s\nsize=%d bytes\nuri=%s\n\n" +
                "Next APK1A stage: lossless-DNG decode → Xiaomi source adapter → Python parity fixtures.",
                name, size, uri);
    }
}
