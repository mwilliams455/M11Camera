package com.m11.diagnostic;

import android.Manifest;
import android.app.Activity;
import android.content.*;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.*;
import android.net.Uri;
import android.os.*;
import android.view.*;
import android.widget.*;
import org.json.JSONObject;
import java.io.File;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** CAPTURE1A: shutter -> single RAW DNG -> unchanged portable M11 Standard renderer.
 * The live feed is explicitly a framing preview, not an M11-look promise. */
public final class M11CaptureActivity extends Activity implements M11CaptureController.Listener,TextureView.SurfaceTextureListener {
    private static final int CAMERA_PERMISSION=4101;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean busy=new AtomicBoolean(),rendering=new AtomicBoolean();
    private M11CaptureController controller;private TextureView texture;private ImageView finishedImage;
    private TextView status,meter,evText;private Spinner cameras;private SeekBar ev;private Button shutter,share,reopen,tools;
    private List<M11CaptureController.Source> sources=Collections.emptyList();private M11CaptureController.Source selected;
    private boolean resumed,ready,discoveryStarted,opening;private Bitmap thumbnail;
    private final ArrayList<Uri> shareUris=new ArrayList<>();

    @Override public void onCreate(Bundle state){
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        controller=new M11CaptureController(this,this);
        LinearLayout body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(10);body.setPadding(pad,pad,pad,pad);
        // Target SDK 36 edge-to-edge: inset controls away from system status/navigation bars.
        body.setOnApplyWindowInsetsListener((v,insets)->{v.setPadding(pad+insets.getSystemWindowInsetLeft(),pad+insets.getSystemWindowInsetTop(),pad+insets.getSystemWindowInsetRight(),pad+insets.getSystemWindowInsetBottom());return insets;});
        TextView title=new TextView(this);title.setText("M11 CAPTURE1A");title.setTextSize(21);body.addView(title);
        TextView scope=new TextView(this);scope.setText("Live feed = framing only. M11 Standard appears after capture.\nSingle RAW · no app HDR · no brand whitelist");scope.setTextSize(12);body.addView(scope);
        cameras=new Spinner(this);body.addView(cameras);
        FrameLayout frame=new FrameLayout(this);frame.setBackgroundColor(0xff171717);
        texture=new TextureView(this);texture.setSurfaceTextureListener(this);frame.addView(texture,new FrameLayout.LayoutParams(-1,-1));
        finishedImage=new ImageView(this);finishedImage.setBackgroundColor(0xff171717);finishedImage.setScaleType(ImageView.ScaleType.FIT_CENTER);finishedImage.setVisibility(View.GONE);
        frame.addView(finishedImage,new FrameLayout.LayoutParams(-1,-1));finishedImage.setOnClickListener(v->finishedImage.setVisibility(View.GONE));
        body.addView(frame,new LinearLayout.LayoutParams(-1,0,1));
        meter=new TextView(this);meter.setText("Camera not opened");meter.setTextSize(13);body.addView(meter);
        evText=new TextView(this);evText.setText("Capture EV 0.00");body.addView(evText);ev=new SeekBar(this);body.addView(ev);
        LinearLayout buttons=new LinearLayout(this);shutter=new Button(this);shutter.setText("Take M11 photo");buttons.addView(shutter,new LinearLayout.LayoutParams(0,-2,2));
        reopen=new Button(this);reopen.setText("Reopen");buttons.addView(reopen,new LinearLayout.LayoutParams(0,-2,1));body.addView(buttons);
        LinearLayout extras=new LinearLayout(this);share=new Button(this);share.setText("Share last set");extras.addView(share,new LinearLayout.LayoutParams(0,-2,1));
        tools=new Button(this);tools.setText("DNG tools");extras.addView(tools,new LinearLayout.LayoutParams(0,-2,1));body.addView(extras);
        status=new TextView(this);status.setTextSize(12);status.setTextIsSelectable(true);status.setText("Grant Camera permission to start.");
        ScrollView log=new ScrollView(this);log.addView(status);body.addView(log,new LinearLayout.LayoutParams(-1,dp(100)));
        setContentView(body);body.requestApplyInsets();
        cameras.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){
            @Override public void onItemSelected(android.widget.AdapterView<?> p,View v,int position,long id){
                if(position>=sources.size()||busy.get())return;
                M11CaptureController.Source next=sources.get(position);
                if(selected!=next){selected=next;ready=false;opening=false;finishedImage.setVisibility(View.GONE);openSelected();}
            }
            @Override public void onNothingSelected(android.widget.AdapterView<?> p){}
        });
        ev.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener(){
            @Override public void onProgressChanged(SeekBar bar,int value,boolean user){
                if(selected==null)return;int code=value+selected.evMin;
                evText.setText(String.format(Locale.US,"Capture EV %+.2f (sensor AE)",code*selected.evStep));
                if(user&&!busy.get())controller.setCompensation(code);
            }
            @Override public void onStartTrackingTouch(SeekBar b){}@Override public void onStopTrackingTouch(SeekBar b){}
        });
        shutter.setOnClickListener(v->{if(!ready||!busy.compareAndSet(false,true))return;
            shareUris.clear();finishedImage.setVisibility(View.GONE);updateControls();controller.capture(displayDegrees());});
        reopen.setOnClickListener(v->{if(busy.get())return;if(checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED){requestPermissions(new String[]{Manifest.permission.CAMERA},CAMERA_PERMISSION);return;}ready=false;opening=false;if(selected==null){discoveryStarted=false;begin();}else openSelected();});
        tools.setOnClickListener(v->{if(!busy.get())startActivity(new Intent(this,MainActivity.class));});
        share.setOnClickListener(v->shareLast());updateControls();
    }
    private int dp(int v){return (int)(v*getResources().getDisplayMetrics().density+.5f);}
    @Override protected void onResume(){super.onResume();resumed=true;begin();}
    private void begin(){
        if(checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED){requestPermissions(new String[]{Manifest.permission.CAMERA},CAMERA_PERMISSION);return;}
        if(!discoveryStarted){discoveryStarted=true;controller.discover();}else openSelected();
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] grant){
        super.onRequestPermissionsResult(request,permissions,grant);
        if(request==CAMERA_PERMISSION){if(grant.length>0&&grant[0]==PackageManager.PERMISSION_GRANTED)begin();else status.setText("Camera permission denied. Tap Reopen to grant it, or use DNG tools.");}
    }
    private void openSelected(){
        if(!resumed||opening||selected==null||!texture.isAvailable()||checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)return;
        opening=true;ready=false;updateControls();controller.start(selected,texture.getSurfaceTexture());transform();
    }
    @Override protected void onPause(){resumed=false;opening=false;ready=false;controller.stop();updateControls();super.onPause();}
    @Override protected void onDestroy(){controller.release(worker::shutdown);if(thumbnail!=null){finishedImage.setImageDrawable(null);thumbnail.recycle();thumbnail=null;}super.onDestroy();}
    @Override public void onConfigurationChanged(Configuration c){super.onConfigurationChanged(c);texture.post(this::transform);}
    @Override public void onSurfaceTextureAvailable(SurfaceTexture t,int w,int h){openSelected();}
    @Override public void onSurfaceTextureSizeChanged(SurfaceTexture t,int w,int h){transform();}
    @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture t){ready=false;opening=false;controller.stopAndReleaseTexture(t);return false;}
    @Override public void onSurfaceTextureUpdated(SurfaceTexture t){}
    private int displayDegrees(){return getWindowManager().getDefaultDisplay().getRotation()*90;}
    private void transform(){
        if(selected==null||texture.getWidth()==0||texture.getHeight()==0)return;
        float w=selected.previewSize.getWidth(),h=selected.previewSize.getHeight(),vw=texture.getWidth(),vh=texture.getHeight();
        int rot=M11CaptureCore.rotation(selected.orientation,displayDegrees(),selected.front);
        float ow=rot%180==0?w:h,oh=rot%180==0?h:w,scale=Math.min(vw/ow,vh/oh);
        Matrix m=new Matrix();m.setScale(w/vw,h/vh);m.postTranslate(-w/2,-h/2);m.postRotate(rot);m.postScale(scale,scale);m.postTranslate(vw/2,vh/2);
        if(selected.front)m.postScale(-1,1,vw/2,vh/2);texture.setTransform(m);
    }
    private void ui(Runnable r){runOnUiThread(()->{if(!isDestroyed()&&!isFinishing())r.run();});}
    private void updateControls(){boolean free=!busy.get();shutter.setEnabled(free&&ready&&resumed);cameras.setEnabled(free);reopen.setEnabled(free);tools.setEnabled(free);ev.setEnabled(free&&ready&&selected!=null&&selected.evMax>selected.evMin);share.setEnabled(free&&!shareUris.isEmpty());}
    @Override public void onSources(List<M11CaptureController.Source> list,String report){ui(()->{
        sources=list;cameras.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,list));
        status.setText(list.isEmpty()?"No compatible RAW sensor exposed to this app.\n"+report:"Available RAW sources: "+list.size()+".\n"+report);
        if(!list.isEmpty()&&selected==null){selected=list.get(0);openSelected();}updateControls();
        if(list.isEmpty())saveFault("No compatible RAW source",report);
    });}
    @Override public void onReady(M11CaptureController.Source source,android.util.Size preview){ui(()->{
        if(source!=selected||!resumed)return;ready=true;ev.setMax(Math.max(0,source.evMax-source.evMin));ev.setProgress(-source.evMin);transform();
        status.setText("Ready: "+source.label()+"\nTap Take M11 photo. Finished image replaces the framing feed; tap it to return.");updateControls();
    });}
    @Override public void onMeter(String text){ui(()->meter.setText(text));}
    @Override public void onStatus(String text){ui(()->status.setText(text));}
    @Override public void onRawSaved(File file,JSONObject info){
        // Called after DngCreator and Image are closed; render worker never owns camera buffers.
        rendering.set(true);worker.execute(()->process(file,info));
    }
    private void process(File file,JSONObject info){
        long start=SystemClock.elapsedRealtime();Uri raw=null,captureJson=null;String outcome;Bitmap image=null;ArrayList<Uri> outputs=new ArrayList<>();
        try{
            ui(()->status.setText("RAW captured. Saving the original and rendering M11 Standard…"));
            raw=M11CaptureStore.publishDng(this,file);outputs.add(raw);
            info.put("sourceDngUri",raw.toString());info.put("sourceDngSha256",M11CaptureStore.sha256(this,raw));info.put("stage","rendering");
            String stem=info.getString("stem");captureJson=M11CaptureStore.saveJson(this,stem+"_CAPTURE.json",info.toString(2));outputs.add(captureJson);
            M11RenderWorkflow.CaptureOutput saved=M11RenderWorkflow.runCaptured(this,raw,stem,info);
            Uri jpeg=M11CaptureStore.uri(saved.jpeg),json=M11CaptureStore.uri(saved.diagnostics);outputs.add(jpeg);outputs.add(json);
            info.put("stage","complete");info.put("jpeg",saved.jpeg);info.put("png",saved.png);info.put("renderJson",saved.diagnostics);info.put("postCaptureMs",SystemClock.elapsedRealtime()-start);
            M11CaptureStore.updateJson(this,captureJson,info.toString(2));
            String previewNote="";try{image=M11CaptureStore.preview(this,jpeg);}catch(Exception e){previewNote="\nSaved JPEG is intact; display preview failed: "+e.getMessage();}
            outcome="M11 photograph saved. Tap image to return to camera.\nDNG/JPEG/PNG: Pictures/M11Camera\nJSON: Download/M11Camera\n"+
                    "Source SHA-256: "+info.getString("sourceDngSha256")+String.format(Locale.US,"\nAfter RAW: %.2f s",(SystemClock.elapsedRealtime()-start)/1000.0)+previewNote;
        }catch(Throwable e){
            outcome="CAPTURE1A failed: "+e.getClass().getSimpleName()+": "+e.getMessage()+"\nOriginal RAW: "+(raw==null?file.getAbsolutePath():raw.toString());
            try{info.put("stage","render_or_save_failed");info.put("error",e.toString());info.put("stack",android.util.Log.getStackTraceString(e));
                if(captureJson==null){captureJson=M11CaptureStore.saveJson(this,info.optString("stem","M11_CAPTURE1A")+"_CAPTURE.json",info.toString(2));outputs.add(captureJson);}else M11CaptureStore.updateJson(this,captureJson,info.toString(2));
            }catch(Exception logError){outcome+="\nDiagnostic save failed: "+logError;}
        }
        final String text=outcome;final Bitmap finalImage=image;rendering.set(false);busy.set(false);
        runOnUiThread(()->{
            if(isDestroyed()||isFinishing()){if(finalImage!=null)finalImage.recycle();return;}
            if(finalImage!=null){finishedImage.setImageDrawable(null);if(thumbnail!=null)thumbnail.recycle();thumbnail=finalImage;finishedImage.setImageBitmap(finalImage);finishedImage.setVisibility(View.VISIBLE);}
            shareUris.clear();for(Uri uri:outputs)if("content".equals(uri.getScheme()))shareUris.add(uri);
            status.setText(text);updateControls();
        });
    }
    @Override public void onFailure(String text,JSONObject info){
        if(!rendering.get())busy.set(false);ui(()->{if("camera_error".equals(info.optString("stage"))){ready=false;opening=false;}status.setText(text+"\nA capture report will be saved to Download/M11Camera.");updateControls();});
        if(!worker.isShutdown())worker.execute(()->{try{info.put("error",text);M11CaptureStore.saveJson(this,"M11_CAPTURE1A_ERROR_"+System.currentTimeMillis()+".json",info.toString(2));}catch(Exception e){ui(()->status.append("\nReport save failed: "+e));}});
    }
    private void saveFault(String message,String report){try{JSONObject info=new JSONObject();info.put("stage","camera_error");info.put("discovery",report);onFailure(message,info);}catch(Exception ignored){}}
    private void shareLast(){
        if(shareUris.isEmpty())return;Intent i=new Intent(Intent.ACTION_SEND_MULTIPLE);i.setType("*/*");i.putParcelableArrayListExtra(Intent.EXTRA_STREAM,new ArrayList<>(shareUris));i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        ClipData clip=ClipData.newRawUri("M11 capture",shareUris.get(0));for(int n=1;n<shareUris.size();n++)clip.addItem(new ClipData.Item(shareUris.get(n)));i.setClipData(clip);
        try{startActivity(Intent.createChooser(i,"Share M11 DNG, JPEG and diagnostics"));}catch(ActivityNotFoundException e){status.setText("No share app available. Files are retained in M11Camera folders.");}
    }
}
