package com.m11.diagnostic;

/** Metadata-only camera -> scene XYZ D50 adapter; no camera/model/profile lookup. */
public final class M11PortableSourceCore {
    private M11PortableSourceCore() {}
    private static final double[] ID = {1,0,0,0,1,0,0,0,1};
    private static final double[] BRADFORD = {.8951,.2664,-.1614,-.7502,1.7135,.0367,.0389,-.0685,1.0296};

    public static String route(DngMetadataReader.Metadata m) {
        boolean dual = m.colorMatrix2 != null && m.calibrationIlluminant2 > 0
                && m.calibrationIlluminant2 != m.calibrationIlluminant1;
        boolean fm = m.forwardMatrix1 != null && (!dual || m.forwardMatrix2 != null);
        return (dual ? "DUAL_" : "SINGLE_") + (fm ? "FORWARD_MATRIX" : "COLOR_MATRIX_BRADFORD");
    }

    public static M11SourceAdapterCore.Result build(DngMetadataReader.Metadata m) {
        if (m == null || !m.sourceTransformReady())
            throw new IllegalArgumentException("DEVICEPORT1A: ColorMatrix1 and positive AsShotNeutral are required");
        double[] ab = m.analogBalance == null ? new double[]{1,1,1} : m.analogBalance.clone();
        positive(ab, "AnalogBalance");
        positive(m.asShotNeutral, "AsShotNeutral");
        double[] c1 = mul(diag(ab), m.effectiveCalibration1());
        double[] c2 = mul(diag(ab), m.effectiveCalibration2());
        boolean dual = route(m).startsWith("DUAL_");
        double f = dual ? M11SourceAdapterCore.findDngInterpolationFactor(
                m.calibrationIlluminant1, m.calibrationIlluminant2, c1, c2,
                m.colorMatrix1, m.colorMatrix2, m.asShotNeutral) : 0;
        double[] cal = dual ? lerp(c1,c2,f) : c1;
        double[] rn = vec(inv(cal),m.asShotNeutral);
        positive(rn, "reference neutral");
        if (route(m).endsWith("FORWARD_MATRIX")) {
            // Reuse the accepted dual-illuminant numerical path without changing its arithmetic.
            if (dual) return M11SourceAdapterCore.buildDualIlluminantTransform(
                    m.calibrationIlluminant1,m.calibrationIlluminant2,c1,c2,
                    m.colorMatrix1,m.colorMatrix2,m.forwardMatrix1,m.forwardMatrix2,m.asShotNeutral);
            double[] fm = M11SourceAdapterCore.normalizeForwardMatrix(m.forwardMatrix1);
            return M11SourceAdapterCore.calculateCameraToXyzD50Transform(
                    fm,fm,c1,c1,m.asShotNeutral,0);
        }
        // Optional ForwardMatrix absent: invert only this DNG's ColorMatrix and
        // adapt its measured neutral to D50. No borrowed sensor/profile matrix.
        double[] cm = dual ? lerp(m.colorMatrix1,m.colorMatrix2,f) : m.colorMatrix1;
        double[] toXyz = inv(mul(cal,cm));
        double[] white = vec(toXyz,m.asShotNeutral);
        positive(white, "scene white XYZ");
        double[] whiteUnit = {white[0]/white[1],1,white[2]/white[1]};
        double[] fromCone = vec(BRADFORD,whiteUnit);
        double[] toCone = vec(BRADFORD,M11SourceAdapterCore.D50_XYZ);
        positive(fromCone, "scene cone white");
        double[] scale = {toCone[0]/fromCone[0],toCone[1]/fromCone[1],toCone[2]/fromCone[2]};
        double[] adapted = mul(mul(inv(BRADFORD),mul(diag(scale),BRADFORD)),toXyz);
        // Keep the established max(referenceNeutral) exposure convention.
        double exposure = Math.max(rn[0],Math.max(rn[1],rn[2]))/white[1];
        for (int i=0;i<9;i++) adapted[i] *= exposure;
        finite(adapted,9,"cameraToXyzD50");
        return new M11SourceAdapterCore.Result(adapted,f,rn);
    }
    private static void positive(double[] v,String name) {
        finite(v,3,name);
        for (double x:v) if(x<=0) throw new IllegalArgumentException(name+" must be positive");
    }
    private static void finite(double[] v,int n,String name) {
        if(v==null||v.length!=n) throw new IllegalArgumentException(name+" length mismatch");
        for(double x:v) if(!Double.isFinite(x)) throw new IllegalArgumentException(name+" is non-finite");
    }
    private static double[] diag(double[] v) {return new double[]{v[0],0,0,0,v[1],0,0,0,v[2]};}
    private static double[] lerp(double[] a,double[] b,double f) {
        finite(a,9,"matrix1");finite(b,9,"matrix2");double[] o=new double[9];
        for(int i=0;i<9;i++)o[i]=a[i]*(1-f)+b[i]*f;return o;
    }
    private static double[] mul(double[] a,double[] b) {
        finite(a,9,"matrix");finite(b,9,"matrix");double[] o=new double[9];
        for(int r=0;r<3;r++)for(int c=0;c<3;c++)
            o[3*r+c]=a[3*r]*b[c]+a[3*r+1]*b[3+c]+a[3*r+2]*b[6+c];return o;
    }
    private static double[] vec(double[] m,double[] v) {
        finite(m,9,"matrix");finite(v,3,"vector");return new double[]{
            m[0]*v[0]+m[1]*v[1]+m[2]*v[2],m[3]*v[0]+m[4]*v[1]+m[5]*v[2],m[6]*v[0]+m[7]*v[1]+m[8]*v[2]};
    }
    private static double[] inv(double[] m) {
        finite(m,9,"matrix");double a=m[0],b=m[1],c=m[2],d=m[3],e=m[4],f=m[5],g=m[6],h=m[7],i=m[8];
        double A=e*i-f*h,B=f*g-d*i,C=d*h-e*g,D=c*h-b*i,E=a*i-c*g,F=b*g-a*h,G=b*f-c*e,H=c*d-a*f,I=a*e-b*d;
        double det=a*A+b*B+c*C;
        if(!Double.isFinite(det)||Math.abs(det)<1e-15)throw new IllegalArgumentException("singular source matrix");
        return new double[]{A/det,D/det,G/det,B/det,E/det,H/det,C/det,F/det,I/det};
    }
}
