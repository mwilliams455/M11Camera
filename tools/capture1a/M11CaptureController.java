package com.m11.diagnostic;

import android.content.Context;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.*;
import android.hardware.camera2.params.*;
import android.media.Image;
import android.media.ImageReader;
import android.os.*;
import android.util.Range;
import android.util.Rational;
import android.util.Size;
import android.view.Surface;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.util.*;

/** Camera2 transport only. No RAW math, M9 exposure allocation, HDR or Leica look here.
 * All ownership/session/pairing state is confined to cameraHandler. DNG encoding completes
 * and closes its Image before the asynchronous M11 renderer is notified. */
public final class M11CaptureController {
    public interface Listener {
        void onSources(List<Source> sources,String report);
        void onReady(Source source,Size preview);
        void onMeter(String text);
        void onStatus(String text);
        void onRawSaved(File file,JSONObject diagnostics);
        void onFailure(String text,JSONObject diagnostics);
    }
    public static final class Source {
        public final String openId, physicalId;
        public final CameraCharacteristics sensor, request;
        public final Size rawSize, previewSize;
        public final boolean front;
        public final int orientation, evMin, evMax;
        public final double evStep;
        Source(String open,String physical,CameraCharacteristics sensor,CameraCharacteristics request) {
            this.openId=open;this.physicalId=physical;this.sensor=sensor;this.request=request;
            Integer cfa=sensor.get(CameraCharacteristics.SENSOR_INFO_COLOR_FILTER_ARRANGEMENT);
            if(cfa==null||cfa<0||cfa>3||sensor.get(CameraCharacteristics.SENSOR_COLOR_TRANSFORM1)==null)
                throw new IllegalArgumentException("Requires conventional RGB Bayer and source ColorTransform1");
            StreamConfigurationMap map=sensor.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            Size[] raw=map==null?null:map.getOutputSizes(ImageFormat.RAW_SENSOR);
            Size[] previews=map==null?null:map.getOutputSizes(SurfaceTexture.class);
            if(raw==null||raw.length==0||previews==null||previews.length==0)
                throw new IllegalArgumentException("No RAW_SENSOR + preview stream");
            int[][] dims=new int[raw.length][2];for(int i=0;i<raw.length;i++){dims[i][0]=raw[i].getWidth();dims[i][1]=raw[i].getHeight();}
            rawSize=raw[M11CaptureCore.sizeIndex(dims)];
            double ratio=(double)rawSize.getWidth()/rawSize.getHeight();
            Size best=null;double score=Double.POSITIVE_INFINITY;
            for(Size size:previews){
                // A modest preview avoids forcing a high-bandwidth RAW+preview combination.
                double p=Math.abs((double)size.getWidth()/size.getHeight()-ratio)*1000+
                        Math.abs((long)size.getWidth()*size.getHeight()-1280L*960)/1_000_000.0;
                if(size.getWidth()>1920||size.getHeight()>1920)p+=100;
                if(p<score){score=p;best=size;}
            }
            previewSize=best;
            front=Objects.equals(sensor.get(CameraCharacteristics.LENS_FACING),CameraCharacteristics.LENS_FACING_FRONT);
            Integer angle=sensor.get(CameraCharacteristics.SENSOR_ORIENTATION);
            if(angle==null)throw new IllegalArgumentException("Sensor orientation missing");orientation=angle;
            Range<Integer> ev=request.get(CameraCharacteristics.CONTROL_AE_COMPENSATION_RANGE);
            Rational step=request.get(CameraCharacteristics.CONTROL_AE_COMPENSATION_STEP);
            evMin=ev==null?0:ev.getLower();evMax=ev==null?0:ev.getUpper();
            evStep=step==null?0:step.doubleValue();
        }
        public String sourceId(){return physicalId==null?openId:physicalId;}
        public String label(){
            float[] focal=sensor.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS);
            String f=focal==null||focal.length==0?"":String.format(Locale.US," / %.1f mm",focal[0]);
            return (front?"Front ":"Rear ")+sourceId()+f+" / "+rawSize+(physicalId==null?"":" via "+openId);
        }
        @Override public String toString(){return label();}
    }
    private final Context context;private final Listener listener;private final CameraManager manager;
    private final HandlerThread thread=new HandlerThread("M11-Capture1A");private final Handler cameraHandler;
    private final M11CaptureCore.Pairer<Image,CaptureResult> pairer=new M11CaptureCore.Pairer<>(Image::close);
    private CameraDevice camera;private CameraCaptureSession session;private ImageReader reader;private Surface preview;
    private Source source;private int generation, compensation, afMode;private long nextShot=0, token=-1, startMs;
    private boolean awaiting, submitted, ready, readyNotified, focusTimedOut;
    private int captureDisplay;private CaptureResult lastResult;private long lastMeterMs;
    private List<CaptureRequest.Key<?>> requestKeys=Collections.emptyList(),physicalKeys=Collections.emptyList();

    public M11CaptureController(Context context,Listener listener){
        this.context=context.getApplicationContext();this.listener=listener;
        manager=(CameraManager)context.getSystemService(Context.CAMERA_SERVICE);
        thread.start();cameraHandler=new Handler(thread.getLooper());
    }
    public void discover(){cameraHandler.post(()->{
        List<Source> found=new ArrayList<>();StringBuilder notes=new StringBuilder();Set<String> direct=new HashSet<>();
        try{
            String[] ids=manager.getCameraIdList();
            for(String id:ids)try{
                CameraCharacteristics c=manager.getCameraCharacteristics(id);
                boolean logical=Build.VERSION.SDK_INT>=28&&has(c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES),CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA);
                if(!logical&&has(c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES),CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_RAW)){
                    found.add(new Source(id,null,c,c));direct.add(id);
                }
            }catch(Exception e){notes.append(id).append(": ").append(e.getMessage()).append('\n');}
            if(Build.VERSION.SDK_INT>=28)for(String id:ids)try{
                CameraCharacteristics c=manager.getCameraCharacteristics(id);
                if(!has(c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES),CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA))continue;
                for(String physical:c.getPhysicalCameraIds())if(!direct.contains(physical))try{
                    CameraCharacteristics p=manager.getCameraCharacteristics(physical);
                    found.add(new Source(id,physical,p,c));
                }catch(Exception e){notes.append(id).append('/').append(physical).append(": ").append(e.getMessage()).append('\n');}
            }catch(Exception e){notes.append(id).append(": ").append(e.getMessage()).append('\n');}
            found.sort(Comparator.comparing((Source s)->s.front).thenComparing(s->s.physicalId!=null).thenComparing(Source::sourceId));
            listener.onSources(found,notes.toString());
        }catch(Exception e){fault("Camera discovery failed: "+e);}
    });}
    public void start(Source selected,SurfaceTexture texture){cameraHandler.post(()->{
        closeInternal("Camera changed");source=selected;compensation=0;lastResult=null;
        final int owner=generation;
        try{
            requestKeys=selected.request.getAvailableCaptureRequestKeys();
            if(requestKeys==null)requestKeys=Collections.emptyList();
            physicalKeys=Build.VERSION.SDK_INT>=28?selected.request.getAvailablePhysicalCameraRequestKeys():Collections.emptyList();
            if(physicalKeys==null)physicalKeys=Collections.emptyList();
            int[] af=selected.sensor.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES);
            afMode=has(af,CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)?CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE:
                    has(af,CaptureRequest.CONTROL_AF_MODE_AUTO)?CaptureRequest.CONTROL_AF_MODE_AUTO:CaptureRequest.CONTROL_AF_MODE_OFF;
            texture.setDefaultBufferSize(selected.previewSize.getWidth(),selected.previewSize.getHeight());
            preview=new Surface(texture);
            reader=ImageReader.newInstance(selected.rawSize.getWidth(),selected.rawSize.getHeight(),ImageFormat.RAW_SENSOR,3);
            reader.setOnImageAvailableListener(r->onImage(owner,r),cameraHandler);
            listener.onStatus("Opening "+selected.label());
            manager.openCamera(selected.openId,new CameraDevice.StateCallback(){
                @Override public void onOpened(CameraDevice d){if(owner!=generation){d.close();return;}camera=d;configure(owner);}
                @Override public void onDisconnected(CameraDevice d){d.close();if(owner==generation){closeInternal("Camera disconnected");fault("Camera disconnected; reopen the camera.");}}
                @Override public void onError(CameraDevice d,int error){d.close();if(owner==generation){closeInternal("Camera error");fault("Camera error "+error+"; another RAW camera can be selected.");}}
            },cameraHandler);
        }catch(Exception e){closeInternal("Open failed");fault("Cannot open RAW camera: "+e);}
    });}
    private void configure(int owner){try{
        CameraCaptureSession.StateCallback callback=new CameraCaptureSession.StateCallback(){
            @Override public void onConfigured(CameraCaptureSession s){
                if(owner!=generation||camera==null){s.close();return;}session=s;
                try{repeat();ready=true;listener.onStatus("Waiting for camera preview…");
                    cameraHandler.postDelayed(()->{if(owner==generation&&!readyNotified){closeInternal("Preview metadata timeout");fault("Preview did not return source-matched metadata; choose another RAW camera.");}},8000);
                }
                catch(Exception e){closeInternal("Preview failed");fault("Preview request failed: "+e);}
            }
            @Override public void onConfigureFailed(CameraCaptureSession s){s.close();if(owner==generation){closeInternal("Session rejected");fault("RAW + preview combination rejected for this camera. Select another source.");}}
        };
        if(source.physicalId!=null&&Build.VERSION.SDK_INT>=28){
            OutputConfiguration p=new OutputConfiguration(preview),r=new OutputConfiguration(reader.getSurface());
            p.setPhysicalCameraId(source.physicalId);r.setPhysicalCameraId(source.physicalId);
            camera.createCaptureSessionByOutputConfigurations(Arrays.asList(p,r),callback,cameraHandler);
        }else camera.createCaptureSession(Arrays.asList(preview,reader.getSurface()),callback,cameraHandler);
    }catch(Exception e){closeInternal("Configure failed");fault("Camera session failed: "+e);}}
    private <T> void setting(CaptureRequest.Builder b,CaptureRequest.Key<T> k,T value){
        if(requestKeys.contains(k))b.set(k,value);
        if(Build.VERSION.SDK_INT>=28&&source.physicalId!=null&&physicalKeys.contains(k))b.setPhysicalCameraKey(k,value,source.physicalId);
    }
    private CaptureRequest.Builder builder(int template)throws CameraAccessException{
        CaptureRequest.Builder b=source.physicalId!=null&&Build.VERSION.SDK_INT>=28?
                camera.createCaptureRequest(template,Collections.singleton(source.physicalId)):camera.createCaptureRequest(template);
        setting(b,CaptureRequest.CONTROL_MODE,CaptureRequest.CONTROL_MODE_AUTO);
        setting(b,CaptureRequest.CONTROL_AE_MODE,CaptureRequest.CONTROL_AE_MODE_ON);
        setting(b,CaptureRequest.CONTROL_AWB_MODE,CaptureRequest.CONTROL_AWB_MODE_AUTO);
        setting(b,CaptureRequest.CONTROL_AF_MODE,afMode);
        setting(b,CaptureRequest.CONTROL_AF_TRIGGER,CaptureRequest.CONTROL_AF_TRIGGER_IDLE);
        setting(b,CaptureRequest.CONTROL_AE_PRECAPTURE_TRIGGER,CaptureRequest.CONTROL_AE_PRECAPTURE_TRIGGER_IDLE);
        setting(b,CaptureRequest.CONTROL_AE_EXPOSURE_COMPENSATION,compensation);
        setting(b,CaptureRequest.FLASH_MODE,CaptureRequest.FLASH_MODE_OFF);
        setting(b,CaptureRequest.CONTROL_ENABLE_ZSL,false);
        if(has(source.sensor.get(CameraCharacteristics.STATISTICS_INFO_AVAILABLE_LENS_SHADING_MAP_MODES),CaptureRequest.STATISTICS_LENS_SHADING_MAP_MODE_ON))
            setting(b,CaptureRequest.STATISTICS_LENS_SHADING_MAP_MODE,CaptureRequest.STATISTICS_LENS_SHADING_MAP_MODE_ON);
        return b;
    }
    private void repeat()throws CameraAccessException{
        CaptureRequest.Builder b=builder(CameraDevice.TEMPLATE_PREVIEW);b.addTarget(preview);
        session.setRepeatingRequest(b.build(),previewCallback,cameraHandler);
    }
    public void setCompensation(int value){cameraHandler.post(()->{
        if(source==null||awaiting)return;compensation=Math.max(source.evMin,Math.min(source.evMax,value));
        if(session!=null)try{repeat();}catch(Exception e){fault("Exposure update failed: "+e);}
    });}
    private CaptureResult sensorResult(TotalCaptureResult total){
        if(source.physicalId==null)return total;
        if(Build.VERSION.SDK_INT>=31)return total.getPhysicalCameraTotalResults().get(source.physicalId);
        if(Build.VERSION.SDK_INT>=28)return total.getPhysicalCameraResults().get(source.physicalId);
        return null;
    }
    private final CameraCaptureSession.CaptureCallback previewCallback=new CameraCaptureSession.CaptureCallback(){
        @Override public void onCaptureCompleted(CameraCaptureSession s,CaptureRequest request,TotalCaptureResult total){
            if(s!=session||source==null)return;
            CaptureResult r=sensorResult(total);if(r==null)return;lastResult=r;
            if(!readyNotified){readyNotified=true;listener.onReady(source,source.previewSize);}
            long now=SystemClock.elapsedRealtime();
            if(now-lastMeterMs>500){lastMeterMs=now;
                Integer iso=r.get(CaptureResult.SENSOR_SENSITIVITY);Long ns=r.get(CaptureResult.SENSOR_EXPOSURE_TIME);
                listener.onMeter("ISO "+iso+(ns==null?"":String.format(Locale.US," · %.4f s",ns/1e9))+
                        String.format(Locale.US," · EV %+.2f",compensation*source.evStep));
            }
            if(awaiting&&!submitted&&now-startMs>250){
                Integer ae=r.get(CaptureResult.CONTROL_AE_STATE),af=r.get(CaptureResult.CONTROL_AF_STATE),awb=r.get(CaptureResult.CONTROL_AWB_STATE);
                boolean exposure=ae==null||ae!=CaptureResult.CONTROL_AE_STATE_SEARCHING&&ae!=CaptureResult.CONTROL_AE_STATE_PRECAPTURE;
                boolean focus=af==null||af!=CaptureResult.CONTROL_AF_STATE_ACTIVE_SCAN&&af!=CaptureResult.CONTROL_AF_STATE_PASSIVE_SCAN;
                boolean white=awb==null||awb!=CaptureResult.CONTROL_AWB_STATE_SEARCHING;
                if(exposure&&focus&&white)submitRaw();
            }
        }
    };
    public void capture(int displayDegrees){cameraHandler.post(()->{
        if(!ready||!readyNotified||camera==null||session==null||awaiting){fault("Camera is not ready for another capture.");return;}
        token=++nextShot;final long shot=token;captureDisplay=displayDegrees;startMs=SystemClock.elapsedRealtime();
        awaiting=true;submitted=false;focusTimedOut=false;pairer.begin(token);
        listener.onStatus("Focusing and metering — single RAW capture…");
        try{
            CaptureRequest.Builder b=builder(CameraDevice.TEMPLATE_PREVIEW);b.addTarget(preview);
            if(afMode!=CaptureRequest.CONTROL_AF_MODE_OFF)setting(b,CaptureRequest.CONTROL_AF_TRIGGER,CaptureRequest.CONTROL_AF_TRIGGER_START);
            session.capture(b.build(),previewCallback,cameraHandler);
            cameraHandler.postDelayed(()->{if(awaiting&&!submitted&&token==shot){focusTimedOut=true;submitRaw();}},1800);
            cameraHandler.postDelayed(()->{if(awaiting&&token==shot)failShot("RAW/result timeout — no matching frame received.");},25_000);
        }catch(Exception e){failShot("Capture preparation failed: "+e);}
    });}
    private void submitRaw(){
        if(!awaiting||submitted||session==null)return;submitted=true;final long shot=token;final int owner=generation;
        try{
            CaptureRequest.Builder b=builder(CameraDevice.TEMPLATE_STILL_CAPTURE);b.addTarget(reader.getSurface());b.addTarget(preview);b.setTag(shot);
            session.capture(b.build(),new CameraCaptureSession.CaptureCallback(){
                @Override public void onCaptureCompleted(CameraCaptureSession s,CaptureRequest req,TotalCaptureResult total){
                    if(owner!=generation||!awaiting||token!=shot)return;
                    try{
                        CaptureResult result=sensorResult(total);
                        if(result==null)throw new IllegalStateException("Physical capture result missing; logical metadata will not be substituted");
                        Long timestamp=result.get(CaptureResult.SENSOR_TIMESTAMP);
                        if(timestamp==null)throw new IllegalStateException("Sensor timestamp missing");
                        acceptPair(pairer.result(shot,timestamp,result));
                    }catch(Exception e){failShot("RAW metadata pairing failed: "+e);}
                }
                @Override public void onCaptureFailed(CameraCaptureSession s,CaptureRequest r,CaptureFailure f){if(owner==generation&&awaiting&&token==shot)failShot("Camera capture failed: reason="+f.getReason());}
                @Override public void onCaptureBufferLost(CameraCaptureSession s,CaptureRequest r,Surface target,long frame){if(owner==generation&&awaiting&&token==shot&&reader!=null&&target==reader.getSurface())failShot("RAW buffer lost at frame "+frame);}
            },cameraHandler);
        }catch(Exception e){failShot("RAW request failed: "+e);}
    }
    private void onImage(int owner,ImageReader r){
        try{
            Image image;
            while((image=r.acquireNextImage())!=null){
                if(owner!=generation||!awaiting||!submitted){image.close();continue;}
                acceptPair(pairer.image(token,image.getTimestamp(),image));
            }
        }catch(Exception e){if(owner==generation&&awaiting)failShot("RAW image delivery failed: "+e);}
    }
    private void acceptPair(M11CaptureCore.Pair<Image,CaptureResult> pair){
        if(pair==null)return;
        File file=null;JSONObject info=diagnostics("raw_paired");Exception failure=null;
        try(Image image=pair.image){
            if(image.getFormat()!=ImageFormat.RAW_SENSOR||!M11CaptureCore.timestampsMatch(image.getTimestamp(),pair.timestamp))
                throw new IllegalStateException("RAW format/timestamp contract failed");
            info.put("imageTimestampNs",image.getTimestamp());info.put("resultTimestampNs",pair.timestamp);
            info.put("pairing","exact_sensor_timestamp");info.put("frameNumber",pair.result.getFrameNumber());
            info.put("rawWidth",image.getWidth());info.put("rawHeight",image.getHeight());
            info.put("rowStride",image.getPlanes()[0].getRowStride());info.put("pixelStride",image.getPlanes()[0].getPixelStride());
            info.put("iso",pair.result.get(CaptureResult.SENSOR_SENSITIVITY));info.put("exposureTimeNs",pair.result.get(CaptureResult.SENSOR_EXPOSURE_TIME));
            info.put("frameDurationNs",pair.result.get(CaptureResult.SENSOR_FRAME_DURATION));
            info.put("actualEvCompensation",pair.result.get(CaptureResult.CONTROL_AE_EXPOSURE_COMPENSATION));
            info.put("aeState",pair.result.get(CaptureResult.CONTROL_AE_STATE));info.put("afState",pair.result.get(CaptureResult.CONTROL_AF_STATE));info.put("awbState",pair.result.get(CaptureResult.CONTROL_AWB_STATE));
            info.put("neutralColorPoint",String.valueOf(Arrays.toString(pair.result.get(CaptureResult.SENSOR_NEUTRAL_COLOR_POINT))));
            info.put("dynamicBlackLevel",String.valueOf(Arrays.toString(pair.result.get(CaptureResult.SENSOR_DYNAMIC_BLACK_LEVEL))));
            info.put("dynamicWhiteLevel",pair.result.get(CaptureResult.SENSOR_DYNAMIC_WHITE_LEVEL));
            LensShadingMap shading=pair.result.get(CaptureResult.STATISTICS_LENS_SHADING_CORRECTION_MAP);
            info.put("lensShadingMapReturned",shading!=null);if(shading!=null){info.put("lensShadingRows",shading.getRowCount());info.put("lensShadingColumns",shading.getColumnCount());}
            int orientation=M11CaptureCore.exifOrientation(M11CaptureCore.rotation(source.orientation,captureDisplay,source.front));info.put("dngOrientation",orientation);
            File root=context.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
            if(root==null)throw new IllegalStateException("Source DNG storage unavailable");
            File dir=new File(root,"M11Camera/Capture1A");
            if(!dir.isDirectory()&&!dir.mkdirs())throw new IllegalStateException("Cannot create source DNG directory");
            String stem="IMG_"+new java.text.SimpleDateFormat("yyyyMMdd_HHmmss_SSS",Locale.US).format(new Date())+"_"+token+"_M11_CAPTURE1A";
            File partial=new File(dir,stem+".dng.part");file=new File(dir,stem+".dng");
            try(DngCreator dng=new DngCreator(source.sensor,pair.result);FileOutputStream out=new FileOutputStream(partial)){
                dng.setOrientation(orientation);dng.setDescription("M11 CAPTURE1A original single RAW; physical metadata authority; no app HDR or RAW pixel mutation.");
                dng.writeImage(out,image);out.getFD().sync();
            }catch(Exception e){partial.delete();throw e;}
            if(!partial.renameTo(file)){partial.delete();throw new IllegalStateException("Cannot finalize source DNG");}
            info.put("stem",stem);info.put("dngBytes",file.length());info.put("captureToDngMs",SystemClock.elapsedRealtime()-startMs);
        }catch(Exception e){failure=e;}
        awaiting=false;submitted=false;pairer.cancel();resumeFocus();
        if(failure==null&&file!=null)listener.onRawSaved(file,info);else listener.onFailure("DNG encoding failed: "+failure,info);
    }
    private JSONObject diagnostics(String stage){
        JSONObject j=new JSONObject();try{
            j.put("schema","m11.capture1a.v1");j.put("stage",stage);j.put("deviceManufacturer",Build.MANUFACTURER);j.put("deviceModel",Build.MODEL);j.put("sdk",Build.VERSION.SDK_INT);
            j.put("singleRawFrame",true);j.put("appHdr",false);j.put("renderExposureCompensation",false);j.put("viewfinderLookMatched",false);j.put("shotToken",token);
            if(source!=null){j.put("openCameraId",source.openId);j.put("physicalCameraId",source.physicalId==null?JSONObject.NULL:source.physicalId);j.put("sourceCharacteristicsId",source.sourceId());j.put("resultAuthority",source.physicalId==null?"same_opened_physical_camera":"explicit_physical_output_and_physical_result");
                j.put("rawRequested",source.rawSize.toString());j.put("previewRequested",source.previewSize.toString());j.put("sensorOrientation",source.orientation);j.put("displayDegrees",captureDisplay);j.put("front",source.front);
                j.put("cfa",source.sensor.get(CameraCharacteristics.SENSOR_INFO_COLOR_FILTER_ARRANGEMENT));j.put("staticWhiteLevel",source.sensor.get(CameraCharacteristics.SENSOR_INFO_WHITE_LEVEL));j.put("requestedEvCompensation",compensation);j.put("evStep",source.evStep);j.put("threeATimedOut",focusTimedOut);}
        }catch(Exception ignored){}return j;
    }
    private void resumeFocus(){if(session==null||camera==null)return;try{
        CaptureRequest.Builder b=builder(CameraDevice.TEMPLATE_PREVIEW);b.addTarget(preview);setting(b,CaptureRequest.CONTROL_AF_TRIGGER,CaptureRequest.CONTROL_AF_TRIGGER_CANCEL);
        session.capture(b.build(),null,cameraHandler);repeat();
    }catch(Exception e){listener.onStatus("RAW finished; preview restart issue: "+e.getMessage());}}
    private void failShot(String why){JSONObject j=diagnostics("capture_failed");awaiting=false;submitted=false;pairer.cancel();resumeFocus();listener.onFailure(why,j);}
    private void fault(String why){listener.onFailure(why,diagnostics("camera_error"));}
    public void stop(){cameraHandler.post(()->closeInternal("Camera paused before capture finished"));}
    public void stopAndReleaseTexture(SurfaceTexture texture){
        if(!cameraHandler.post(()->{closeInternal("Preview surface closed");texture.release();}))texture.release();
    }
    public void release(Runnable after){cameraHandler.post(()->{closeInternal("Camera closed");after.run();thread.quitSafely();});}
    private void closeInternal(String why){
        generation++;ready=false;readyNotified=false;
        if(awaiting){awaiting=false;submitted=false;pairer.cancel();listener.onFailure(why,diagnostics("capture_cancelled"));}else pairer.cancel();
        if(session!=null){session.close();session=null;}if(camera!=null){camera.close();camera=null;}
        if(reader!=null){reader.close();reader=null;}if(preview!=null){preview.release();preview=null;}
    }
    private static boolean has(int[] values,int key){if(values!=null)for(int v:values)if(v==key)return true;return false;}
}
