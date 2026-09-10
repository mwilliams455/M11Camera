package com.m11.diagnostic;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Saves the controlled RENDER1A outputs without altering pixel values. */
public final class M11RenderOutputWriter {
    private M11RenderOutputWriter() {}

    public static final class Result {
        public final String png;
        public final String jpeg;
        public final String diagnostics;

        Result(String png, String jpeg, String diagnostics) {
            this.png = png;
            this.jpeg = jpeg;
            this.diagnostics = diagnostics;
        }
    }

    public static Result save(Activity activity, Bitmap bitmap, String diagnosticsJson, String stem) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            String png = saveImage(activity, bitmap, stem + ".png", "image/png", Bitmap.CompressFormat.PNG, 100);
            String jpg = saveImage(activity, bitmap, stem + ".jpg", "image/jpeg", Bitmap.CompressFormat.JPEG, 98);
            String json = saveJson(activity, diagnosticsJson, stem + ".json");
            return new Result(png, jpg, json);
        }
        File picturesRoot = activity.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
        File documentsRoot = activity.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS);
        if (picturesRoot == null || documentsRoot == null) {
            throw new IOException("app external-files storage is unavailable");
        }
        File pictures = new File(picturesRoot, "M11Camera");
        File documents = new File(documentsRoot, "M11Camera");
        if (!pictures.exists() && !pictures.mkdirs()) throw new IOException("cannot create fallback Pictures/M11Camera");
        if (!documents.exists() && !documents.mkdirs()) throw new IOException("cannot create fallback Documents/M11Camera");
        File png = new File(pictures, stem + ".png");
        File jpg = new File(pictures, stem + ".jpg");
        File json = new File(documents, stem + ".json");
        try (OutputStream out = new FileOutputStream(png)) {
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) throw new IOException("PNG compression failed");
        }
        try (OutputStream out = new FileOutputStream(jpg)) {
            if (!bitmap.compress(Bitmap.CompressFormat.JPEG, 98, out)) throw new IOException("JPEG compression failed");
        }
        try (OutputStream out = new FileOutputStream(json)) {
            out.write(diagnosticsJson.getBytes(StandardCharsets.UTF_8));
        }
        return new Result(png.getAbsolutePath(), jpg.getAbsolutePath(), json.getAbsolutePath());
    }

    private static String saveImage(Activity activity, Bitmap bitmap, String name, String mime,
                                    Bitmap.CompressFormat format, int quality) throws IOException {
        ContentResolver resolver = activity.getContentResolver();
        ContentValues values = new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
        values.put(MediaStore.MediaColumns.MIME_TYPE, mime);
        values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/M11Camera");
        values.put(MediaStore.MediaColumns.IS_PENDING, 1);
        Uri uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
        if (uri == null) throw new IOException("MediaStore image insert failed");
        boolean ok = false;
        try (OutputStream out = resolver.openOutputStream(uri, "w")) {
            if (out == null) throw new IOException("MediaStore image output stream unavailable");
            if (!bitmap.compress(format, quality, out)) throw new IOException(name + " compression failed");
            ok = true;
        } finally {
            if (!ok) resolver.delete(uri, null, null);
        }
        values.clear();
        values.put(MediaStore.MediaColumns.IS_PENDING, 0);
        resolver.update(uri, values, null, null);
        return uri.toString();
    }

    private static String saveJson(Activity activity, String text, String name) throws IOException {
        ContentResolver resolver = activity.getContentResolver();
        ContentValues values = new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
        values.put(MediaStore.MediaColumns.MIME_TYPE, "application/json");
        values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/M11Camera");
        values.put(MediaStore.MediaColumns.IS_PENDING, 1);
        Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri == null) throw new IOException("MediaStore diagnostics insert failed");
        boolean ok = false;
        try (OutputStream out = resolver.openOutputStream(uri, "w")) {
            if (out == null) throw new IOException("MediaStore diagnostics output stream unavailable");
            out.write(text.getBytes(StandardCharsets.UTF_8));
            ok = true;
        } finally {
            if (!ok) resolver.delete(uri, null, null);
        }
        values.clear();
        values.put(MediaStore.MediaColumns.IS_PENDING, 0);
        resolver.update(uri, values, null, null);
        return uri.toString();
    }
}
