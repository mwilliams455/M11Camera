package com.m11.diagnostic;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.Arrays;
public final class PortableSourceSelfTest {
    static int passed=0;
    static double[] id(){return new double[]{1,0,0,0,1,0,0,0,1};}
    static final double[] CM1={.8359375,-.171875,-.1328125,-.46875,1.3984375,.046875,-.0859375,.3359375,.40625};
    static final double[] CM2={1.28125,-.484375,-.2265625,-.5859375,1.59375,.140625,-.046875,.1796875,.703125};
    static final double[] CAL={1.03125,0,0,0,1,0,0,0,1.015625};
    static final double[] FM={.6328125,.109375,.21875,.21875,.7578125,.0234375,-.0390625,-.453125,1.3203125};
    static DngMetadataReader.Metadata fixture(){
        DngMetadataReader.Metadata m=new DngMetadataReader.Metadata();
        m.colorMatrix1=CM1.clone();m.colorMatrix2=CM2.clone();m.cameraCalibration1=CAL.clone();m.cameraCalibration2=CAL.clone();
        m.forwardMatrix1=FM.clone();m.forwardMatrix2=FM.clone();m.calibrationIlluminant1=21;m.calibrationIlluminant2=17;
        m.asShotNeutral=new double[]{.32421875,1,.62109375};return m;
    }
    static void check(boolean b,String label){if(!b)throw new AssertionError(label);passed++;}
    static void close(double[] a,double[] b,double eps,String label){
        check(a.length==b.length,label+" length");for(int i=0;i<a.length;i++)if(!Double.isFinite(a[i])||Math.abs(a[i]-b[i])>eps)throw new AssertionError(label+" "+i+" "+a[i]+" != "+b[i]);passed++;
    }
    static void rejects(Runnable r,String label){try{r.run();}catch(IllegalArgumentException e){passed++;return;}throw new AssertionError("accepted "+label);}
    static void neutral(DngMetadataReader.Metadata m){
        M11SourceAdapterCore.Result r=M11PortableSourceCore.build(m);
        double[] target=M11SourceAdapterCore.D50_XYZ.clone();double max=Arrays.stream(r.referenceNeutral).max().getAsDouble();
        for(int i=0;i<3;i++)target[i]*=max;
        close(M11SourceAdapterCore.applyCameraToXyz(m.asShotNeutral,r.cameraToXyzD50),target,1e-10,"neutral -> D50");
    }
    public static void main(String[] args)throws Exception{
        DngMetadataReader.Metadata m=fixture();
        M11SourceAdapterCore.Result old=M11SourceAdapterCore.buildDualIlluminantTransform(21,17,CAL,CAL,CM1,CM2,FM,FM,m.asShotNeutral);
        M11SourceAdapterCore.Result now=M11PortableSourceCore.build(m);
        check(Arrays.equals(old.cameraToXyzD50,now.cameraToXyzD50),"validated dual matrix bit-exact");
        check(old.interpolationFactor==now.interpolationFactor,"validated factor exact");
        check(Arrays.equals(old.referenceNeutral,now.referenceNeutral),"validated neutral exact");
        for(String brand:new String[]{"Xiaomi","Google","Samsung","Sony","Unknown"}){
            m.make=brand;m.model="synthetic sensor";
            check(Arrays.equals(now.cameraToXyzD50,M11PortableSourceCore.build(m).cameraToXyzD50),"brand invariant "+brand);
        }
        m.analogBalance=new double[]{1,1,1};check(Arrays.equals(now.cameraToXyzD50,M11PortableSourceCore.build(m).cameraToXyzD50),"identity analog exact");
        m=fixture();m.colorMatrix2=null;m.forwardMatrix2=null;check(M11PortableSourceCore.route(m).equals("SINGLE_FORWARD_MATRIX"),"single FM");neutral(m);
        m=fixture();m.forwardMatrix1=null;m.forwardMatrix2=null;check(M11PortableSourceCore.route(m).equals("DUAL_COLOR_MATRIX_BRADFORD"),"dual CM only");neutral(m);
        m=fixture();m.colorMatrix2=null;m.forwardMatrix1=null;m.forwardMatrix2=null;check(M11PortableSourceCore.route(m).equals("SINGLE_COLOR_MATRIX_BRADFORD"),"single CM only");neutral(m);
        m=fixture();m.calibrationIlluminant2=21;check(M11PortableSourceCore.route(m).startsWith("SINGLE_"),"equal illuminants");neutral(m);
        m=fixture();m.analogBalance=new double[]{2,1,.8};neutral(m);
        m.forwardMatrix1=null;m.forwardMatrix2=null;neutral(m);
        m=fixture();m.cameraCalibration1=null;m.cameraCalibration2=null;neutral(m);
        final DngMetadataReader.Metadata noCm=fixture();noCm.colorMatrix1=null;rejects(()->M11PortableSourceCore.build(noCm),"missing matrix no fallback");
        final DngMetadataReader.Metadata zero=fixture();zero.asShotNeutral[0]=0;rejects(()->M11PortableSourceCore.build(zero),"zero neutral");
        final DngMetadataReader.Metadata nan=fixture();nan.colorMatrix1[4]=Double.NaN;rejects(()->M11PortableSourceCore.build(nan),"NaN CM");
        final DngMetadataReader.Metadata badAb=fixture();badAb.analogBalance=new double[]{1,-1,1};rejects(()->M11PortableSourceCore.build(badAb),"negative analog");
        final DngMetadataReader.Metadata singular=fixture();singular.cameraCalibration1=new double[9];singular.cameraCalibration2=new double[9];rejects(()->M11PortableSourceCore.build(singular),"singular calibration");
        final DngMetadataReader.Metadata badFm=fixture();badFm.forwardMatrix1=new double[9];rejects(()->M11PortableSourceCore.build(badFm),"zero forward matrix");
        for(String file:args){try(FileChannel ch=FileChannel.open(Path.of(file))){DngMetadataReader.Metadata d=DngMetadataReader.read(ch);neutral(d);check(d.analogBalance!=null,"AnalogBalance parsed");}}
        System.out.println("DEVICEPORT1A source assertions passed: "+passed);
        System.out.println("Existing dual-illuminant source output: bit-for-bit unchanged for the validated fixture.");
    }
}
