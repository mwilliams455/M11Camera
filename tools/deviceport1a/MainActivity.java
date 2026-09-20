package com.m11.diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** Offline device-independent source validation and frozen M11 Standard rendering. */
public final class MainActivity extends Activity {
    private static final int IDENTIFY=1101, RENDER=1105;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean busy=new AtomicBoolean();
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout body=new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(20*getResources().getDisplayMetrics().density);body.setPadding(pad,pad,pad,pad);
        TextView title=new TextView(this);title.setText("M11 RENDER1J — DevicePort1A");title.setTextSize(22);body.addView(title);
        TextView scope=new TextView(this);
        scope.setText("Offline M11 Standard renderer. No phone-brand, model, lens-ID or fixed-resolution whitelist.\n\n"+
                "Supports conventional RGB Bayer DNG with usable source calibration and ISO metadata. Unsupported formats fail with a reason, never a borrowed phone profile.\n\n"+
                "Source DNG metadata → XYZ D50 → firmware DirectK → unchanged M11 tone/colour. No HDR or added local tone mapping.\n\n"+
                "This is a DNG renderer, not yet a live capture/viewfinder app. New devices need photograph testing.");body.addView(scope);
        Button render=new Button(this);render.setText("Select DNG — render M11 Standard");render.setOnClickListener(v->choose(RENDER));body.addView(render);
        Button inspect=new Button(this);inspect.setText("Select DNG — inspect source metadata");inspect.setOnClickListener(v->choose(IDENTIFY));body.addView(inspect);
        Button self=new Button(this);self.setText("Run bundled RAW parity self-test");self.setOnClickListener(v->execute(()->M11SyntheticRawSelfTest.run(this)));body.addView(self);
        status=new TextView(this);status.setText("Ready. DevicePort1A / DIRECTK1A; source capability checks enabled.");status.setTextIsSelectable(true);body.addView(status);
        ScrollView scroll=new ScrollView(this);scroll.addView(body);setContentView(scroll);
    }
    private interface Task {String run() throws Exception;}
    private void execute(Task task) {
        if(!busy.compareAndSet(false,true)){status.setText("A render or inspection is already running.");return;}
        status.setText("Processing selected source…");
        worker.execute(()->{
            String result;
            try{result=task.run();}catch(Throwable e){result="DEVICEPORT1A failed\n"+e.getClass().getSimpleName()+": "+e.getMessage();}
            finally{busy.set(false);}
            final String text=result;
            runOnUiThread(()->{if(!isFinishing()&&!isDestroyed())status.setText(text);});
        });
    }
    private void choose(int request) {
        if(busy.get()){status.setText("A render or inspection is already running.");return;}
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("*/*");
        startActivityForResult(i,request);
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null||(request!=IDENTIFY&&request!=RENDER))return;
        Uri uri=data.getData();
        try{getContentResolver().takePersistableUriPermission(uri,data.getFlags()&Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(SecurityException ignored){}
        if(request==RENDER)execute(()->M11RenderWorkflow.run(this,uri));else execute(()->inspect(uri));
    }
    private String inspect(Uri uri)throws Exception {
        try(ParcelFileDescriptor fd=getContentResolver().openFileDescriptor(uri,"r")) {
            if(fd==null)throw new IllegalStateException("No readable source descriptor");
            String report=M11NativeRawBridge.identifyFd(fd.getFd());
            try(FileInputStream in=new FileInputStream(fd.getFileDescriptor())) {
                DngMetadataReader.Metadata m=DngMetadataReader.read(in.getChannel());
                DngIsoReader.Result iso=DngIsoReader.read(in.getChannel());
                report+="\nSource make/model (diagnostic only): "+m.make+" / "+m.model+"\nISO: "+(iso.present()?iso.iso:"missing")+
                        "\nAsShotNeutral: "+Arrays.toString(m.asShotNeutral)+"\nAnalogBalance: "+Arrays.toString(m.analogBalance);
                M11SourceAdapterCore.Result s=M11PortableSourceCore.build(m);
                return report+"\nCalibration route: "+M11PortableSourceCore.route(m)+"\nCamera to XYZ D50: "+Arrays.toString(s.cameraToXyzD50)+
                        "\nNo pixels rendered by this inspection. Use the separate render action.";
            }
        }
    }
    @Override protected void onDestroy(){worker.shutdown();super.onDestroy();}
}
