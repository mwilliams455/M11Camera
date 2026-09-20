#!/usr/bin/env python3
"""CAPTURE1A orchestration-only overlay, applied AFTER RENDER1J/DEVICEPORT1A."""
from pathlib import Path
import hashlib,json,shutil

def one(s,a,b):
    if s.count(a)!=1: raise ValueError('capture anchor mismatch: '+a[:100])
    return s.replace(a,b,1)

def patch_workflow(s):
    begin='        long startedNs = System.nanoTime();'
    end='        String stem = '
    original=s[s.index(begin):s.index(end)]
    s=one(s,'    public static String run(Activity activity, Uri sourceUri) throws Exception {', '''    public static final class CaptureOutput {
        public final String report, png, jpeg, diagnostics;
        CaptureOutput(M11RenderOutputWriter.Result saved, String report) {
            this.report=report; this.png=saved.png; this.jpeg=saved.jpeg; this.diagnostics=saved.diagnostics;
        }
    }
    public static String run(Activity activity, Uri sourceUri) throws Exception {
        return execute(activity, sourceUri, null, null).report;
    }
    public static CaptureOutput runCaptured(Activity activity, Uri sourceUri, String stem, JSONObject capture) throws Exception {
        if(stem==null || stem.length()>160 || !stem.matches("[A-Za-z0-9_-]+") || capture==null)
            throw new IllegalArgumentException("CAPTURE1A requires a safe capture identity and metadata");
        return execute(activity, sourceUri, stem, capture);
    }
    private static CaptureOutput execute(Activity activity, Uri sourceUri, String captureStem, JSONObject capture) throws Exception {''')
    s=one(s,'        JSONObject diagnostics = new JSONObject();','''        if (captureStem != null) stem = captureStem;
        JSONObject diagnostics = new JSONObject();
        if (capture != null) diagnostics.put("capture", new JSONObject(capture.toString()));''')
    s=one(s,'        return "M11 RENDER1J DEVICEPORT1A complete\\n" +','        return new CaptureOutput(saved, "M11 RENDER1J DEVICEPORT1A complete\\n" +')
    s=one(s,'CAT42 exact hardware arithmetic remains a separate research boundary.";','CAT42 exact hardware arithmetic remains a separate research boundary.");')
    assert original==s[s.index(begin):s.index(end)], 'Source/RAW/target processing changed'
    return s

def main():
    root=Path.cwd();p=Path(__file__).resolve().parent;java=root/'app/src/main/java/com/m11/diagnostic'
    freeze=[root/'native/m11_renderer/m11_reference_renderer_core.h',root/'native/libraw_probe/m11_raw_oracle_params.h',root/'app/src/main/cpp/m11_render_jni.cpp',root/'app/src/main/cpp/m11_portable_raw_gate.h',root/'app/src/main/assets/m11_reference_tables_v1.bin']
    freeze += [java/n for n in ['M11InternalEntryCore.java','M11SourceAdapterCore.java','M11PortableSourceCore.java','DngMetadataReader.java','M11RenderBridge.java','M11RenderOutputWriter.java']]
    def hashes():return {str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in freeze}
    before=hashes()
    wf=java/'M11RenderWorkflow.java'
    # Pin the delivered materialized RENDER1J workflow, not just a permissive text anchor.
    expected='1cf2d65df4fb09aa769e1c0db16346336c45a020e6ef63300facf0a28eb4a997'
    if hashlib.sha256(wf.read_bytes()).hexdigest()!=expected:raise ValueError('RENDER1J workflow hash mismatch')
    wf.write_text(patch_workflow(wf.read_text()))
    for name in ['M11CaptureCore.java','M11CaptureController.java','M11CaptureStore.java','M11CaptureActivity.java']:
        shutil.copyfile(p/name,java/name)
    (root/'app/src/main/AndroidManifest.xml').write_text((p/'AndroidManifest.xml').read_text())
    g=root/'app/build.gradle.kts';s=g.read_text()
    s=one(s,'com.m11.diagnostic.render1j','com.m11.diagnostic.capture1a')
    s=one(s,'versionCode = 14','versionCode = 15')
    s=one(s,'0.1.13-render1j-deviceport1a','0.2.0-capture1a');g.write_text(s)
    after=hashes()
    if after!=before:raise ValueError('Frozen renderer/source/decoder/output altered')
    report={'before':before,'after':after,'allFrozenFilesEqual':True,'rawAndSourceAndTargetProcessingBlockIdentical':True,'captureEntry':'runCaptured -> execute (same engine as imported DNG)','livePreviewLookMatched':False}
    Path('M11_CAPTURE1A_FROZEN_HASHES.json').write_text(json.dumps(report,indent=2)+'\n')
    print('CAPTURE1A applied: capture + DNG handoff + diagnostics only; 11 frozen files unchanged')
if __name__=='__main__':main()
