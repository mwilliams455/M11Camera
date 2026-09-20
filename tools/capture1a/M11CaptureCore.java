package com.m11.diagnostic;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/** Android-free capture rules. No camera name, model, target colour or pixel processing. */
public final class M11CaptureCore {
    private M11CaptureCore() {}
    public static int rotation(int sensorDegrees, int displayDegrees, boolean front) {
        if (sensorDegrees % 90 != 0 || displayDegrees % 90 != 0)
            throw new IllegalArgumentException("Camera/display orientation must be a multiple of 90");
        return Math.floorMod(sensorDegrees + (front ? displayDegrees : -displayDegrees), 360);
    }
    public static int exifOrientation(int degrees) {
        switch (Math.floorMod(degrees, 360)) {
            case 0: return 1; case 90: return 6; case 180: return 3; case 270: return 8;
            default: throw new IllegalArgumentException("Non-right-angle orientation");
        }
    }
    /** Prefer the largest advertised RAW up to 16 MP; otherwise the smallest available.
     * This selects an actual sensor stream, never downsamples or assumes fixed dimensions. */
    public static int sizeIndex(int[][] sizes) {
        if (sizes == null || sizes.length == 0) throw new IllegalArgumentException("No RAW sizes");
        int best=-1, smallest=-1; long bestArea=0, minArea=Long.MAX_VALUE;
        for (int i=0;i<sizes.length;i++) {
            if (sizes[i]==null || sizes[i].length!=2 || sizes[i][0]<=0 || sizes[i][1]<=0) continue;
            long n=(long)sizes[i][0]*sizes[i][1];
            if (n<minArea) {minArea=n;smallest=i;}
            if (n<=16_000_000L && n>bestArea) {bestArea=n;best=i;}
        }
        if (smallest<0) throw new IllegalArgumentException("Invalid RAW dimensions");
        return best<0 ? smallest : best;
    }
    public static boolean timestampsMatch(long image, long result) {
        return image>0 && image==result;
    }
    public static final class Pair<I,R> {
        public final I image; public final R result; public final long timestamp;
        Pair(I image,R result,long timestamp) {this.image=image;this.result=result;this.timestamp=timestamp;}
    }
    /** Single shot, exact timestamps, bounded owned images. Caller must serialize methods.
     * A matched image transfers to the caller; every discarded image is closed exactly once. */
    public static final class Pairer<I,R> {
        private final Consumer<I> close;
        private final LinkedHashMap<Long,I> images=new LinkedHashMap<>();
        private long token=-1, resultTimestamp=-1;
        private R result;
        public Pairer(Consumer<I> close) {this.close=close;}
        public void begin(long token) {
            if (token<0) throw new IllegalArgumentException("Negative token");
            cancel(); this.token=token;
        }
        public Pair<I,R> image(long shot,long timestamp,I image) {
            if (image==null) throw new IllegalArgumentException("Null image");
            if (shot!=token || token<0 || timestamp<=0 || (result!=null && timestamp!=resultTimestamp)) {
                close.accept(image); return null;
            }
            I old=images.put(timestamp,image); if (old!=null && old!=image) close.accept(old);
            while (images.size()>2) {
                Map.Entry<Long,I> first=images.entrySet().iterator().next();
                images.remove(first.getKey()); close.accept(first.getValue());
            }
            return match();
        }
        public Pair<I,R> result(long shot,long timestamp,R result) {
            if (shot!=token || token<0) return null;
            if (timestamp<=0 || result==null) throw new IllegalArgumentException("Missing capture timestamp/result");
            this.result=result; this.resultTimestamp=timestamp;
            java.util.Iterator<Map.Entry<Long,I>> it=images.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<Long,I> e=it.next();
                if (!timestampsMatch(e.getKey(),timestamp)) {it.remove();close.accept(e.getValue());}
            }
            return match();
        }
        private Pair<I,R> match() {
            I image=images.remove(resultTimestamp);
            if (result==null || image==null) return null;
            Pair<I,R> p=new Pair<>(image,result,resultTimestamp);
            cancel(); return p;
        }
        public void cancel() {
            for (I i:images.values()) close.accept(i);
            images.clear(); result=null; resultTimestamp=-1; token=-1;
        }
    }
}
