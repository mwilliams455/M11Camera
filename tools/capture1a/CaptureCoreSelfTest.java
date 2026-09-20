package com.m11.diagnostic;
import java.util.HashMap;
import java.util.Map;
public final class CaptureCoreSelfTest {
    static int n;
    static void check(boolean b) { n++; if(!b) throw new AssertionError("check "+n); }
    public static void main(String[] args) {
        for(int s=0;s<360;s+=90)for(int d=0;d<360;d+=90) {
            check(M11CaptureCore.rotation(s,d,false)==(s-d+360)%360);
            check(M11CaptureCore.rotation(s,d,true)==(s+d)%360);
            check(M11CaptureCore.exifOrientation(M11CaptureCore.rotation(s,d,false))>=1);
        }
        check(M11CaptureCore.exifOrientation(0)==1);check(M11CaptureCore.exifOrientation(90)==6);
        check(M11CaptureCore.exifOrientation(180)==3);check(M11CaptureCore.exifOrientation(270)==8);
        check(!M11CaptureCore.timestampsMatch(0,0));check(!M11CaptureCore.timestampsMatch(11,12));
        check(M11CaptureCore.timestampsMatch(12,12));
        check(M11CaptureCore.sizeIndex(new int[][]{{8000,6000},{4096,3072},{1920,1080}})==1);
        check(M11CaptureCore.sizeIndex(new int[][]{{8192,6144},{6000,4000}})==1);
        check(M11CaptureCore.sizeIndex(new int[][]{{0,9},{4080,3072}})==1);
        Map<String,Integer> closed=new HashMap<>();
        M11CaptureCore.Pairer<String,String> p=new M11CaptureCore.Pairer<>(s->closed.merge(s,1,Integer::sum));
        p.begin(1);check(p.image(1,100,"a")==null);
        M11CaptureCore.Pair<String,String> m=p.result(1,100,"r");check(m!=null&&m.image.equals("a"));
        check(!closed.containsKey("a"));check(p.result(1,100,"repeat")==null);
        p.image(1,100,"late");check(closed.get("late")==1);
        p.begin(2);check(p.result(2,200,"r2")==null);check(p.image(2,199,"wrong")==null);
        check(closed.get("wrong")==1);m=p.image(2,200,"b");check(m!=null&&m.timestamp==200);
        p.begin(3);p.image(3,300,"stale");check(p.result(3,301,"r3")==null);
        check(closed.get("stale")==1);check(p.image(3,301,"c")!=null);
        p.begin(4);p.image(3,1,"old_generation");check(closed.get("old_generation")==1);
        p.image(4,0,"zero");check(closed.get("zero")==1);
        p.image(4,1,"x");p.image(4,2,"y");p.image(4,3,"z");check(closed.get("x")==1);
        p.cancel();p.cancel();check(closed.get("y")==1&&closed.get("z")==1);
        p.begin(5);p.image(5,1,"replaced");p.image(5,1,"replacement");
        check(closed.get("replaced")==1);p.begin(6);check(closed.get("replacement")==1);
        try {p.result(6,0,"bad");throw new AssertionError();}catch(IllegalArgumentException expected){n++;}
        try {M11CaptureCore.exifOrientation(45);throw new AssertionError();}catch(IllegalArgumentException expected){n++;}
        try {M11CaptureCore.sizeIndex(new int[0][]);throw new AssertionError();}catch(IllegalArgumentException expected){n++;}
        for(int i:closed.values())check(i==1);
        System.out.println("CAPTURE1A core: "+n+" assertions passed");
    }
}
