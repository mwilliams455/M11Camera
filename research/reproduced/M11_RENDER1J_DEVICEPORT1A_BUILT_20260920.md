# M11 RENDER1J DEVICEPORT1A — built, physical-device validation next

Date: 2026-09-20.

## Scope and result

Removed the production renderer's Xiaomi 15 Ultra source-DNG whitelist. This is an offline DNG renderer, not capture or live-viewfinder integration. Manufacturer-independent source handling does not mean every RAW format, CPU ABI or Android version is supported.

Rendering baseline: `c7e0e36d8560c76813ef41be0d257ba13a1c6502`, `work/render1h-cat42yq3a-placement1a`.
New branch: `work/render1j-deviceport1a`.
Build/code commit: `b08b08b09b6afc25e9cb565bcf10f64b582cc83b`.
Workflow: `.github/workflows/m11-render1j-deviceport1a.yml`.
Successful run: `35501314342`; job `106053452009`.
APK artifact: `10602197974`; evidence artifact: `10602512163`.

APK version: `0.1.13-render1j-deviceport1a`, versionCode 14.
Application ID: `com.m11.diagnostic.render1j`, separate from RENDER1I for side-by-side testing.
Manifest application label: `M11 RENDER1J Portable`.
APK bytes: 3,754,610.
APK SHA-256: `3fb519569c7379886d4fc4af1a1cd9ba3729c713a1b6b97ded37d0ab54d02f88`.
The download matched the CI hash. APK signature v2 verified in CI. Local binary-manifest parsing confirmed label, application ID and version; aapt's badging label field was empty despite the correct string attribute.

## Reviewed reference implementations

M9 source snapshot: `mwilliams455/M9Camera_refresh@f5ce9888f62e3f6dced298a0edaf537005fc7d5b` (latest successful M9LIVEGL1U build inspected, not the older main branch).

Reviewed `M9CfaResolver.java`, `M9RawSensorDescriptor.java`, `apply-m9cam-nativeprospective1a.py`, `apply-m9cam-nohdr1a-sourcecal2a-cmfix.py`, and `apply-m9cam-m9sensortarget1a.py` in that source/overlay tree. Important contract: actual source metadata before common XYZ D50; shared Leica target afterwards. M9's source-calibration correction preserves ColorMatrix rows and normalizes ForwardMatrix only. The M9 production assertion distinguishes source Camera2 metadata from the recovered M9 target and forbids consuming historical Cobalt calibration in that production path. Some historical/control data is retained by M9; this is not a claim of repository-wide deletion.

Monochrome snapshot: `mwilliams455/MMonochrome@32658cddf7b154b6fbd29814250c2c6aa1887822`, `research/deviceport3a-rawstride-pack1a`.
Reviewed `docs/MONO_PHYSICAL_SENSOR_SOURCE_ADAPTER_CONTRACT.md` and `apk/mono1a/promote-sourceadapter1a-portable.py`. Its source/common-scene boundary and unsupported-format rejection apply here; its monochrome luminance target does not.

Pinned source collection run: `35500646936`, artifact `10602296634`, archive SHA-256 `a1ce6058bf21aab188ab1d5766a3198b255737b5549a11548729e2c0f8cfd32e`.

## Actual old restriction

The M11 native render gate required Make=Xiaomi, Model=25010PN30G, 4096x3072 raw and visible dimensions, zero crop margins, one fixed CFA filter word, maximum=1023 and packed_dng_load_raw(). This was a source-file whitelist, not merely the UI text or an installation-model restriction.

The existing source matrix implementation was already metadata-driven. It did not need replacing with M9's target renderer.

## Implemented changes

`tools/deviceport1a/apply.py` applies after the existing H/I materialization. It byte-gates the original materialized JNI source and changes the source boundary only.

- New capability descriptor has no make/model/camera-ID fields. Accepts conventional RGGB/GRBG/GBRG/BGGR three-colour single-image integer Bayer DNG, valid source geometry/margins and white level, subject to decoder and buffer limits.
- LibRaw keeps ownership of source black/white normalization, CFA, crop, row pitch and orientation. The RAW/AHD parameters remain unchanged. No new phone-specific shading correction is added; full optical shading portability is not claimed.
- Java geometry checks now use the decoder's active/oriented dimensions, not the first TIFF IFD, which can describe a preview.
- The selected DNG's own calibration and neutral remain the source authority, regardless of the device running the app. No host-phone Camera2 matrices are substituted for imported DNG data.
- AnalogBalance is parsed and composed with CameraCalibration. Identity analog balance preserves the old accepted numerical path.
- Original dual-ForwardMatrix implementation is reused unchanged. Single-illuminant cases are supported. Where ForwardMatrix is absent, the new explicit source-only route inverts that DNG's ColorMatrix and Bradford-adapts its inferred neutral to D50, retaining the existing max(referenceNeutral) exposure convention. This is a source adapter extension, not recovered M11 target arithmetic or a borrowed device profile.
- Missing/invalid required calibration fails; no Xiaomi/Cobalt source-profile fallback exists.
- Generic inspection/render UI replaces the phone-specific diagnostic actions. Old real-Xiaomi probe/export and historical internal-entry A/B classes are excluded from this APK. Bundled synthetic parity checks remain isolated tests, not runtime source profiles.
- JPEG quality stays 98; PNG and JSON outputs remain enabled.

## Frozen target evidence

All five files remained hash-identical across portability materialization:

```
native/m11_renderer/m11_reference_renderer_core.h
1abb03df1d40124a657b10ae0942f86e0dc47d747a126971a43a75b1d10e5c98

app/src/main/java/com/m11/diagnostic/M11InternalEntryCore.java
adc3a6ff1908a24e9d56b7fc1d41a5a236546d069fb30e943145f4df062b93bc

app/src/main/java/com/m11/diagnostic/M11SourceAdapterCore.java
9cacf817d8082f87695f1b9bfd1bcb190a819c7bbba6a31c030aca5e2227d208

native/libraw_probe/m11_raw_oracle_params.h
796314f5effe3529a48c9bd4fceb28860854a16693ac970bb79e698165474d9d

app/src/main/assets/m11_reference_tables_v1.bin
54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219
```

The JNI pixel-render loop was separately compared byte-for-byte as source text. It is unchanged. The JNI file as a whole changes because its input gate and diagnostics change.

Keep DIRECTK1A, identity CC0, frozen RENDER1H downstream, inactive Cat25, Cat42 code/512 and hardware-exact=false. No guessed MCC, M9 tone/colour target, HDR or local tone mapping was introduced.

## Executed checks

- 33 existing Android JVM/JUnit tests: pass, no failures/errors/skips.
- 37 standalone C++ source-capability assertions: pass, with address/undefined-behaviour sanitizers.
- 87 Java source/metadata assertions: pass. The validated 15 Ultra fixture's source matrix, interpolation factor and reference neutral are bit-for-bit identical to the old source adapter. This is not a new physical-device same-photo comparison.
- 16 synthetic DNGs decoded with the pinned rawpy 0.27.1 / LibRaw 0.22.1 oracle: all four Bayer layouts, white levels 1023/4095/16383/65535, crop/no-crop and all eight TIFF orientations. Geometry and uint16 RGB outputs checked.
- Two additional identical-pixel synthetic DNGs with different vendor labels produced identical oracle output.
- APK embedded target asset remains 23,150 bytes with the canonical hash. ARM64 native renderer contains the new generic JNI entry; the old model string and real-Xiaomi render entry are absent.
- All seven delivered source/test payload files matched their committed Git blob identities locally.

The synthetic decoder checks are host-side LibRaw-oracle tests. They are not a full Android JNI image render on a physical phone. No new physical device, real sensor image-quality, live capture or viewfinder validation was performed.

## Remaining compatibility limits and next test

APK: Android API 26+ and arm64-v8a. Input: a compatible conventional integer RGB Bayer DNG, usable source calibration/neutral and ISO; source sizes and memory must be supported by the decoder/device. Linear RGB DNG, X-Trans, non-RGB CFA, unsupported multi-image/floating RAW and missing required calibration are not claimed supported. Specialized DNG/profile extensions and every device's optical/preprocessing behavior are not exhaustively validated.

Render a real DNG from a non-15-Ultra source next, retain PNG/JPEG/JSON, and inspect native sourceCapabilityGate, CFA/geometry, calibration route, orientation, and visual output. Use RENDER1I as a separate same-DNG control where that older gate allows it. Do not resume MCC research as a prerequisite for this device test.
