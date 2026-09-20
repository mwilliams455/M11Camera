#!/usr/bin/env python3
"""Apply DEVICEPORT1A only after the frozen RENDER1I build materialization."""
from pathlib import Path
import hashlib,re,shutil
root=Path.cwd(); payload=Path(__file__).resolve().parent
java=root/'app/src/main/java/com/m11/diagnostic'; native=root/'app/src/main/cpp'
def one(s,a,b):
    if s.count(a)!=1:raise RuntimeError('anchor mismatch: '+a[:100])
    return s.replace(a,b,1)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
frozen=[root/'native/m11_renderer/m11_reference_renderer_core.h',java/'M11InternalEntryCore.java',java/'M11SourceAdapterCore.java',root/'native/libraw_probe/m11_raw_oracle_params.h',root/'app/src/main/assets/m11_reference_tables_v1.bin']
before={str(p.relative_to(root)):digest(p) for p in frozen}
p=native/'m11_render_jni.cpp';s=p.read_text();old=s
if digest(p)!='89265792c287e6fdf35b76705a3b3bfe9569c959bde590c7019f6a0928c98ed2':raise RuntimeError('frozen RENDER1I JNI prerequisite hash mismatch')
s=one(s,'#include "m11_raw_oracle_params.h"','#include "m11_raw_oracle_params.h"\n#include "m11_portable_raw_gate.h"')
a=s.index('constexpr unsigned kWidth =');b=s.index('double elapsedMs',a);s=s[:a]+s[b:]
a=s.index('    // Preserve the existing REALRAW1C');b=s.index('    const auto unpack_start',a)
s=s[:a]+'''    const m11raw::PortableRawDescriptor sourceDescriptor{
        id.dng_version,id.raw_count,static_cast<unsigned>(id.colors),id.filters,
        sizes.raw_width,sizes.raw_height,sizes.width,sizes.height,
        sizes.left_margin,sizes.top_margin,color.maximum,std::string(id.cdesc, strnlen(id.cdesc,sizeof(id.cdesc)))};
    const std::string sourceCfa = m11raw::validatePortableRaw(sourceDescriptor);
    if (decoder.decoder_name == nullptr) throw std::runtime_error("DEVICEPORT1A: decoder unavailable");
    const unsigned sourceRawWidth=sizes.raw_width, sourceRawHeight=sizes.raw_height;
    const unsigned sourceVisibleWidth=sizes.width, sourceVisibleHeight=sizes.height;
    const unsigned sourceTop=sizes.top_margin, sourceLeft=sizes.left_margin;
    const unsigned sourceMaximum=color.maximum;
    const int sourceFlip=sizes.flip;

'''+s[b:]
s=one(s,'    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);','''    if (raw.imgdata.rawdata.raw_image == nullptr ||
        raw.imgdata.sizes.raw_pitch < static_cast<unsigned>(raw.imgdata.sizes.raw_width)*2u)
        throw std::runtime_error("DEVICEPORT1A: unpacked integer Bayer buffer/stride unavailable");
    m11raw::applyRawpy0271OracleParams(raw.imgdata.params, false);''')
s=one(s,'    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3) {','''    const unsigned expectedWidth=(sourceFlip & 4) ? sourceVisibleHeight : sourceVisibleWidth;
    const unsigned expectedHeight=(sourceFlip & 4) ? sourceVisibleWidth : sourceVisibleHeight;
    if (image->width!=expectedWidth || image->height!=expectedHeight)
        throw std::runtime_error("DEVICEPORT1A: LibRaw-oriented active dimensions mismatch");
    if (image->type != LIBRAW_IMAGE_BITMAP || image->bits != 16 || image->colors != 3) {''')
s=one(s,'    report << "realXiaomiIdentityGate=true\\n";','''    report << "devicePortRevision=DEVICEPORT1A\\n";
    report << "sourceCapabilityGate=true\\nmanufacturerWhitelist=false\\n";
    report << "sourceMake=" << id.make << "\\nsourceModel=" << id.model << '\\n';
    report << "sourceCfa=" << sourceCfa << '\\n';
    report << "sourceRawWidth=" << sourceRawWidth << "\\nsourceRawHeight=" << sourceRawHeight << '\\n';
    report << "sourceVisibleWidth=" << sourceVisibleWidth << "\\nsourceVisibleHeight=" << sourceVisibleHeight << '\\n';
    report << "sourceTopMargin=" << sourceTop << "\\nsourceLeftMargin=" << sourceLeft << '\\n';
    report << "sourceWhiteLevel=" << sourceMaximum << "\\nsourceLibRawFlip=" << sourceFlip << '\\n';
    report << "expectedOutputWidth=" << expectedWidth << "\\nexpectedOutputHeight=" << expectedHeight << '\\n';
    report << "sourceRawNormalization=LibRaw_DNG_black_white_crop_CFA\\n";
    report << "sourceLensShadingPolicy=no_additional_phone_specific_correction\\n";''')
s=s.replace('nativeRenderRealXiaomiStandardFd','nativeRenderStandardFd')
# Pixel arithmetic and raw-decode parameters may not be changed by this overlay.
start='    const auto render_start';end='    const auto render_end'
assert old[old.index(start):old.index(end)]==s[s.index(start):s.index(end)]
p.write_text(s);shutil.copy2(payload/'m11_portable_raw_gate.h',native/'m11_portable_raw_gate.h')
p=java/'M11RenderBridge.java';s=p.read_text().replace('nativeRenderRealXiaomiStandardFd','nativeRenderStandardFd')
s=s[:s.index('/**')]+'''/** Portable Bayer DNG bridge; source metadata -> DirectK; canonical target tables required. */\n'''+s[s.index('public final class'):];p.write_text(s)
p=java/'DngMetadataReader.java';s=p.read_text()
s=one(s,'    private static final int TAG_AS_SHOT_NEUTRAL = 50728;','    private static final int TAG_ANALOG_BALANCE = 50727;\n    private static final int TAG_AS_SHOT_NEUTRAL = 50728;')
s=one(s,'        public double[] asShotNeutral;','        public double[] analogBalance;\n        public double[] asShotNeutral;')
s=one(s,'''            return matrix9(colorMatrix1) && matrix9(colorMatrix2)
                    && matrix9(forwardMatrix1) && matrix9(forwardMatrix2)
                    && vector3(asShotNeutral)
                    && calibrationIlluminant1 >= 0 && calibrationIlluminant2 >= 0;''','''            if (!matrix9(colorMatrix1) || !vector3(asShotNeutral)) return false;
            for (double v : colorMatrix1) if (!Double.isFinite(v)) return false;
            for (double v : asShotNeutral) if (!Double.isFinite(v) || v <= 0) return false;
            return true;''')
s=one(s,'                    case TAG_AS_SHOT_NEUTRAL:','''                    case TAG_ANALOG_BALANCE:
                        if (out.analogBalance == null) out.analogBalance = requireCount(value.numbers(), 3, "AnalogBalance");
                        break;
                    case TAG_AS_SHOT_NEUTRAL:''');p.write_text(s)
shutil.copy2(payload/'M11PortableSourceCore.java',java/'M11PortableSourceCore.java')
shutil.copy2(payload/'MainActivity.java',java/'MainActivity.java')
p=java/'M11RenderWorkflow.java';s=p.read_text()
a=s.index('        M11SourceAdapterCore.Result source =');b=s.index('        // DIRECTK1A promotion:',a)
s=s[:a]+'        M11SourceAdapterCore.Result source = M11PortableSourceCore.build(meta);\n'+s[b:]
a=s.index('        boolean orientationSwapsAxes =');b=s.index('        Bitmap oriented = rawBitmap;',a)
s=s[:a]+'''        // LibRaw owns crop/CFA/orientation. A preview IFD's dimensions are not RAW geometry.
        JSONObject nativeMetadata = parseNativeDiagnostics(nativeResult.diagnostics);
        int expectedNativeWidth = nativeMetadata.getInt("expectedOutputWidth");
        int expectedNativeHeight = nativeMetadata.getInt("expectedOutputHeight");
        if (rawBitmap.getWidth()!=expectedNativeWidth || rawBitmap.getHeight()!=expectedNativeHeight) {
            rawBitmap.recycle();
            throw new IOException("DEVICEPORT1A: native bitmap/geometry contract mismatch");
        }
'''+s[b:]
s=s.replace('required Xiaomi dual-illuminant DNG source tags are incomplete','DNG ColorMatrix1 or positive AsShotNeutral is missing/invalid')
s=s.replace('Xiaomi characterization/WB','source DNG characterization/WB').replace('Xiaomi WB/characterization','source DNG WB/characterization')
s=s.replace('controlled Xiaomi DNG','metadata-calibrated Bayer DNG')
s=s.replace('m11camera.render1i.directk1a.device.v1','m11camera.render1j.deviceport1a.device.v1')
s=s.replace('_M11_RENDER1I_DIRECTK1A','_M11_RENDER1J_DEVICEPORT1A').replace('M11 RENDER1I DIRECTK1A complete','M11 RENDER1J DEVICEPORT1A complete')
s=s.replace('m11SensorColorSpecAppliedToXiaomi','m11SensorColorSpecAppliedToSource')
s=one(s,'        diagnostics.put("sourceRawSize", meta.imageWidth + "x" + meta.imageHeight);','''        diagnostics.put("sourceRawSize", nativeMetadata.getString("sourceRawWidth") + "x" + nativeMetadata.getString("sourceRawHeight"));
        diagnostics.put("metadataFirstIfdSize", meta.imageWidth + "x" + meta.imageHeight);
        diagnostics.put("sourceCalibrationRoute", M11PortableSourceCore.route(meta));
        diagnostics.put("sourceCalibrationAuthority", "selected_DNG_metadata_not_host_phone");
        diagnostics.put("sourceManufacturerWhitelist", false);
        diagnostics.put("sourceCobaltRuntimeDependency", false);
        diagnostics.put("sourcePhoneProfileFallback", false);
        diagnostics.put("sourceAnalogBalance", jsonArray(meta.analogBalance == null ? new double[]{1,1,1} : meta.analogBalance));
        diagnostics.put("newDevicePhotographicValidation", "pending");''')
p.write_text(s)
# Legacy phone-specific parity probes remain repository research, but not in this APK.
p=native/'CMakeLists.txt';s=p.read_text();a=s.index('# The original identify');b=s.index('add_library',a);s=s[:a]+'# DEVICEPORT1A: identify + synthetic self-test + portable renderer only.\n'+s[b:]
s=s.replace('    m11_realraw_probe_jni.cpp\n','').replace('    m11_realraw_export_jni.cpp\n','');p.write_text(s)
for name in ['M11RealRawProbe.java','M11RealRawProbeBridge.java','M11RealRawAhdExport.java','M11InternalEntryAbWorkflow.java']:
    (java/name).unlink()
p=root/'app/build.gradle.kts';s=p.read_text().replace('versionCode = 13','versionCode = 14').replace('0.1.12-render1i-directk1a','0.1.13-render1j-deviceport1a').replace('com.m11.diagnostic.render1i','com.m11.diagnostic.render1j');p.write_text(s)
p=root/'app/src/main/AndroidManifest.xml';p.write_text(p.read_text().replace('M11 RENDER1I DirectK','M11 RENDER1J Portable'))
assert before=={str(p.relative_to(root)):digest(p) for p in frozen}
print('DEVICEPORT1A applied; target math, DirectK, RAW/AHD parameters and asset unchanged.')
import json
Path('M11_DEVICEPORT_FROZEN_HASHES.json').write_text(json.dumps(before,indent=2)+'\n')
