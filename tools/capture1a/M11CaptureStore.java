package com.m11.diagnostic;
import android.content.*;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.*;
import android.provider.MediaStore;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Publish original RAW and small capture reports. The existing renderer owns PNG/JPEG output. */
public final class M11CaptureStore {
    private M11CaptureStore() {}
    public static Uri publishDng(Context c,File file)throws Exception{
        if(Build.VERSION.SDK_INT<29)return Uri.fromFile(file);
        ContentValues v=values(file.getName(),"image/x-adobe-dng","Pictures/M11Camera");
        ContentResolver r=c.getContentResolver();Uri uri=r.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI,v);
        if(uri==null)throw new IOException("MediaStore refused source DNG");
        boolean ok=false;
        try{
            try(InputStream in=new FileInputStream(file);OutputStream out=r.openOutputStream(uri,"w")){
                if(out==null)throw new IOException("Source DNG stream unavailable");copy(in,out);
            }
            // Preserve exact source-file identity before deleting the private staging copy.
            if(!sha256(c,Uri.fromFile(file)).equals(sha256(c,uri)))throw new IOException("Published DNG hash mismatch");
            ContentValues done=new ContentValues();done.put(MediaStore.MediaColumns.IS_PENDING,0);
            if(r.update(uri,done,null,null)!=1)throw new IOException("Cannot publish completed source DNG");
            ok=true;file.delete();return uri;
        }finally{if(!ok)r.delete(uri,null,null);}
    }
    public static Uri saveJson(Context c,String name,String text)throws IOException{
        if(Build.VERSION.SDK_INT<29){
            File root=c.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS);
            if(root==null)throw new IOException("Documents storage unavailable");
            File dir=new File(root,"M11Camera");if(!dir.isDirectory()&&!dir.mkdirs())throw new IOException("Cannot create report directory");
            File file=new File(dir,name);try(OutputStream out=new FileOutputStream(file)){out.write(text.getBytes(StandardCharsets.UTF_8));}return Uri.fromFile(file);
        }
        ContentResolver r=c.getContentResolver();Uri uri=r.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI,values(name,"application/json","Download/M11Camera"));
        if(uri==null)throw new IOException("Capture JSON insert failed");
        boolean ok=false;try{
            updateJson(c,uri,text);ContentValues done=new ContentValues();done.put(MediaStore.MediaColumns.IS_PENDING,0);
            if(r.update(uri,done,null,null)!=1)throw new IOException("Cannot publish capture JSON");ok=true;return uri;
        }finally{if(!ok)r.delete(uri,null,null);}
    }
    public static void updateJson(Context c,Uri uri,String text)throws IOException{
        try(OutputStream out=c.getContentResolver().openOutputStream(uri,"wt")){
            if(out==null)throw new IOException("Report stream unavailable");out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }
    private static ContentValues values(String name,String mime,String path){
        ContentValues v=new ContentValues();v.put(MediaStore.MediaColumns.DISPLAY_NAME,name);v.put(MediaStore.MediaColumns.MIME_TYPE,mime);
        v.put(MediaStore.MediaColumns.RELATIVE_PATH,path);v.put(MediaStore.MediaColumns.IS_PENDING,1);return v;
    }
    public static Uri uri(String value){return value.startsWith("/")?Uri.fromFile(new File(value)):Uri.parse(value);}
    public static Bitmap preview(Context c,Uri uri)throws IOException{
        BitmapFactory.Options o=new BitmapFactory.Options();o.inJustDecodeBounds=true;
        try(InputStream in=c.getContentResolver().openInputStream(uri)){if(in==null)throw new IOException("JPEG unavailable");BitmapFactory.decodeStream(in,null,o);}
        o.inJustDecodeBounds=false;o.inSampleSize=1;
        while(Math.max(o.outWidth,o.outHeight)/o.inSampleSize>1600)o.inSampleSize*=2;
        try(InputStream in=c.getContentResolver().openInputStream(uri)){if(in==null)throw new IOException("JPEG unavailable");Bitmap b=BitmapFactory.decodeStream(in,null,o);if(b==null)throw new IOException("JPEG preview decode failed");return b;}
    }
    public static String sha256(Context c,Uri uri)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=c.getContentResolver().openInputStream(uri)){
            if(in==null)throw new IOException("Source unavailable for hash");byte[] b=new byte[1024*1024];int n;while((n=in.read(b))!=-1)if(n>0)d.update(b,0,n);
        }StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.US,"%02x",b&255));return s.toString();
    }
    private static void copy(InputStream in,OutputStream out)throws IOException{byte[] b=new byte[1024*1024];int n;while((n=in.read(b))!=-1)if(n>0)out.write(b,0,n);}
}
