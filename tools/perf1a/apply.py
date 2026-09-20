#!/usr/bin/env python3
"""PERF1A after CAPTURE1A: remove research computations, not photographic operations."""
from pathlib import Path
import hashlib,json,shutil
BASE_JNI='e216df93b1965378e71f935e6a9b8580a4cb343c8ff532ed87cc949955bba049'
def one(s,a,b):
    if s.count(a)!=1: raise ValueError('PERF1A anchor mismatch: '+a[:90])
    return s.replace(a,b,1)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def patch_native(s):
    if hashlib.sha256(s.encode()).hexdigest()!=BASE_JNI:raise ValueError('CAPTURE1A JNI gate mismatch')
    s=one(s,'#include "m11_reference_renderer_core.h"','#include "m11_reference_renderer_core.h"\n#include "m11_production_pixel.h"')
    start=s.index('    Vec01Stats camera_stats{};');end=s.index('    const auto render_start',start)
    s=s[:start]+'''    Vec01Stats current_output_sample_stats{};
    std::uint64_t diagnostic_samples = 0;

'''+s[end:]
    start=s.index('        m11::render::RenderConfig config;');end=s.index('        constexpr double kU16Norm',start)
    s=s[:start]+s[end:]
    start=s.index('                const auto tr = m11::render::renderPixelTraceValidated');end=s.index('                dst[x * 4u]',start)
    s=s[:start]+'''                const auto out = m11::production::savedPixelValidated(m11_rgb, tables);
                // 16x16 grid of OUTPUT diagnostics only; all image pixels use the same target.
                if ((x & 15u) == 0u && (y & 15u) == 0u) {
                    current_output_sample_stats.add(out);
                    ++diagnostic_samples;
                }
'''+s[end:]
    start=s.index('    report << "toneLookup.below0=');end=s.index('    jclass object_class',start)
    s=s[:start]+'''    report << "performanceRevision=PERF1A\\n";
    report << "targetPixelMathChanged=false\\n";
    report << "researchCounterfactualsEvaluated=false\\n";
    report << "diagnosticsMode=current_output_sampled_16x16\\n";
    report << "diagnosticSamples=" << diagnostic_samples << "\\n";
    report << "sampledStatsAreFullFrameExtrema=false\\n";
    report << "savedBitmapUsesCat42Candidate=true\\n";
    appendVec01Stats(report, "currentOutputPreClampSample", current_output_sample_stats, diagnostic_samples);

'''+s[end:]
    s=one(s,'stageIsolationOnly=true\\n','stageIsolationOnly=false\\n')
    s=one(s,'counterfactualNoGamma=gammaYBypassedFromBaselineYccTrace\\n','counterfactualNoGamma=not_evaluated\\n')
    s=one(s,'counterfactualNoChroma=standardChromaScaleBypassedFromBaselineYccTrace\\n','counterfactualNoChroma=not_evaluated\\n')
    assert 'no_gamma_preclamp_stats' not in s
    return s

def patch_writer(s):
    # Same codec settings and ordering. Measure each encode+save+publish operation.
    s=one(s,'import android.os.Build;','import android.os.Build;\nimport android.os.SystemClock;\nimport org.json.JSONObject;\nimport org.json.JSONException;')
    s=one(s,'        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {','        final long saveStartNs=SystemClock.elapsedRealtimeNanos();\n        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {\n            long pngStartNs=SystemClock.elapsedRealtimeNanos();')
    s=one(s,'            String jpg = saveImage','            double pngMs=msSince(pngStartNs);\n            long jpegStartNs=SystemClock.elapsedRealtimeNanos();\n            String jpg = saveImage')
    s=one(s,'            String json = saveJson(activity, diagnosticsJson, stem + ".json");','''            double jpegMs=msSince(jpegStartNs);
            String timed=timedDiagnostics(diagnosticsJson,pngMs,jpegMs,msSince(saveStartNs));
            String json = saveJson(activity, timed, stem + ".json");''')
    s=one(s,'        try (OutputStream out = new FileOutputStream(png)) {','        long pngStartNs=SystemClock.elapsedRealtimeNanos();\n        try (OutputStream out = new FileOutputStream(png)) {')
    s=one(s,'        try (OutputStream out = new FileOutputStream(jpg)) {','        double pngMs=msSince(pngStartNs);\n        long jpegStartNs=SystemClock.elapsedRealtimeNanos();\n        try (OutputStream out = new FileOutputStream(jpg)) {')
    s=one(s,'        try (OutputStream out = new FileOutputStream(json)) {','        double jpegMs=msSince(jpegStartNs);\n        String timed=timedDiagnostics(diagnosticsJson,pngMs,jpegMs,msSince(saveStartNs));\n        try (OutputStream out = new FileOutputStream(json)) {')
    s=one(s,'out.write(diagnosticsJson.getBytes(StandardCharsets.UTF_8));','out.write(timed.getBytes(StandardCharsets.UTF_8));')
    before='    private static String saveImage('
    helper='''    private static double msSince(long start) {
        return (SystemClock.elapsedRealtimeNanos()-start)/1e6;
    }
    private static String timedDiagnostics(String original,double png,double jpeg,double imagesTotal) throws IOException {
        try {
            JSONObject report=new JSONObject(original), t=new JSONObject();
            t.put("pngEncodeSavePublishMs",png);
            t.put("jpegEncodeSavePublishMs",jpeg);
            t.put("imagesTotalBeforeJsonMs",imagesTotal);
            t.put("jsonWriteIncluded",false);
            t.put("codecOnlyTiming",false);
            report.put("outputSaveTiming",t);
            return report.toString(2);
        } catch(JSONException e) { throw new IOException("Cannot attach image-save timings",e); }
    }

'''
    s=one(s,before,helper+before)
    assert 'Bitmap.CompressFormat.JPEG, 98' in s and 'Bitmap.CompressFormat.PNG, 100' in s
    return s

def main():
    root=Path.cwd();here=Path(__file__).resolve().parent;java=root/'app/src/main/java/com/m11/diagnostic'
    frozen=['native/m11_renderer/m11_reference_renderer_core.h','native/libraw_probe/m11_raw_oracle_params.h','app/src/main/cpp/m11_portable_raw_gate.h','app/src/main/assets/m11_reference_tables_v1.bin','app/src/main/cpp/CMakeLists.txt']
    frozen += ['app/src/main/java/com/m11/diagnostic/'+p+'.java' for p in ['M11SourceAdapterCore','M11PortableSourceCore','M11InternalEntryCore','DngMetadataReader','M11RenderBridge','M11CaptureController','M11CaptureCore','M11CaptureStore']]
    before={p:sha(root/p) for p in frozen}
    jni=root/'app/src/main/cpp/m11_render_jni.cpp';old=jni.read_text()
    Path('work/perf1a').mkdir(parents=True,exist_ok=True);Path('work/perf1a/legacy_jni.cpp').write_text(old)
    jni.write_text(patch_native(old));shutil.copyfile(here/'m11_production_pixel.h',jni.parent/'m11_production_pixel.h')
    writer=java/'M11RenderOutputWriter.java';writer.write_text(patch_writer(writer.read_text()))
    g=root/'app/build.gradle.kts';s=g.read_text()
    s=one(s,'com.m11.diagnostic.capture1a','com.m11.diagnostic.capture1b')
    s=one(s,'versionCode = 15','versionCode = 16');s=one(s,'0.2.0-capture1a','0.2.1-capture1b-perf1a');g.write_text(s)
    manifest=root/'app/src/main/AndroidManifest.xml';manifest.write_text(one(manifest.read_text(),'android:label="M11 Capture1A"','android:label="M11 Capture1B PERF1A"'))
    act=java/'M11CaptureActivity.java';act.write_text(one(act.read_text(),'title.setText("M11 CAPTURE1A")','title.setText("M11 CAPTURE1B · PERF1A")'))
    wf=java/'M11RenderWorkflow.java';s=wf.read_text()
    s=one(s,'        JSONObject diagnostics = new JSONObject();','''        JSONObject diagnostics = new JSONObject();
        diagnostics.put("performanceRevision", "PERF1A");
        diagnostics.put("researchCounterfactualsEvaluated", false);
        diagnostics.put("targetPixelMathChanged", false);''')
    wf.write_text(s)
    after={p:sha(root/p) for p in frozen};assert after==before
    report={'before':before,'after':after,'frozenFilesEqual':True,'legacyJniSha256':BASE_JNI,'photoJniSha256':sha(jni),'productionHeaderSha256':sha(jni.parent/'m11_production_pixel.h'),'compilerFlagsChanged':False,'jpegQuality':98,'pngRetained':True,'viewfinderStillFramingOnly':True}
    Path('M11_PERF1A_FREEZE.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PERF1A applied; 13 source/target/capture/compiler boundaries frozen. No quality reduction.')
if __name__=='__main__':main()
