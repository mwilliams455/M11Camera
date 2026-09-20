# M11 CAPTURE1B PERF1A — built, on-device timing/parity next

Date: 2026-09-20.

## Build and scope

Base: CAPTURE1A `53864283eaa002b2cf4ab8bced7cf47990bbe2bf`.
Branch: `work/capture1b-perf1a`.
Build commit: `7a22da1cfb2433356ab2c32162a5f3291ca413d3`.
Successful workflow run: `35511912089`; job `106081168659`.
APK artifact: `10605353200`; evidence artifact: `10605832745`.

APK: version `0.2.1-capture1b-perf1a`, versionCode 16.
Application ID: `com.m11.diagnostic.capture1b`; separate from CAPTURE1A for comparison.
Actual binary-manifest label: `M11 Capture1B PERF1A`.
APK bytes: 3,779,142. SHA-256:
`a081d9131251c8d7a3a750eff0c3808679d5a9eddc15dd43a4be02763814280b`.
APK ZIP SHA-256: `14bbb8a21564c635445db7a91b7320fb21c96dab16ffc34faf84ff32127e3546`.
Evidence ZIP SHA-256: `5bbfb93573934b7f6c7aab58b7c2064f0d701aaf82310dd5f53de2a7308e9c29`.
Downloaded ZIPs, APK hash, binary manifest and embedded asset were independently checked. Signature-v2 verification passed in CI.

This is a performance/diagnostic separation, not a colour, tone, exposure or metering correction. Private photographs and full private diagnostics were not uploaded to this repository or CI.

## Change

The previous materialized JNI (SHA-256 `e216df93b1965378e71f935e6a9b8580a4cb343c8ff532ed87cc949955bba049`) computed full-resolution historical comparison routes and extensive statistics although only its final CAT42 image was saved.

The new `m11_production_pixel.h` keeps the actual saved sequence: source-to-internal matrix, identity CC0, existing Standard tone, componentwise gamma, CC1/clip, YC, current CAT42, inverse YC, clamp and the same RGBA8 quantization. The old trace core is reused for its unchanged CC0/tone operations with its unused CC1/Y-gamma/chroma disabled; those historical operations were not the saved path.

Historical no-gamma/no-chroma/old-placement output computations are no longer run. Output diagnostics use a clearly labelled 16x16 sample grid; all photograph pixels remain full-resolution. Sampled extrema are explicitly not full-frame extrema. Source capability, source authority and actual timing fields remain.

New output JSON records separate PNG and JPEG encode/save/publish intervals. These are not codec-only timings. The subsequent JSON write is not included. Original `totalWorkflowMs` remains a pre-save measurement; postCaptureMs is the broader capture-app measurement.

## Frozen boundaries

13 files remain hash-identical: RAW/AHD parameters, shared reference core, portable capability gate, target asset, CMake/compiler configuration, source adapters, DirectK, DNG metadata reader, render bridge, capture controller/core/store. No precision reduction, interpolation approximation, multithreading, demosaic change, RAW resize, HDR, exposure normalization or phone-specific profile was added. JPEG remains quality98 and PNG is retained.

The native library is expected to change because code paths were removed. Its new hash is `9f42c4bd976698aa2083d88684fcc0e46e472220160cd466dba2823a923f139a`; do not claim native-library identity with CAPTURE1A. Asset hash stays `54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219`.

## Tests actually executed

- CI: 33 JVM/JUnit tests, zero failures/errors/skips.
- CI: previous capture-core 89 assertions and portable source/decoder prerequisite tests passed.
- CI: 1,063,344 synthetic inputs across all four CC1 ISO bands, including complete 16-bit neutral ramps, seeded extended-range colours and explicit boundary values. Tested at host -O0 and -O2: zero differing double components and zero differing quantized components.
- Local: one private full-resolution DNG decoded by pinned rawpy0.27.1/LibRaw0.22.1. The original full JNI computation and new photo-only computation yielded zero different bytes across 12,582,912 RGBA pixels. Repeated using the final production header downloaded from CI, with the same result.
- Local: source payload Git blob identities and downloaded file hashes checked.

The local parity test compares two host implementations. It is not a byte-for-byte comparison of old and new Android captures. Original Android output in the conversation was resized/re-encoded, so it cannot provide a lossless full-frame device oracle.

Host loop benchmarks showed a reduction in calculation time; no measured phone speedup or capture-to-JPEG deadline is claimed. Decode, AHD, Bitmap access, encoding and device scheduling are separate costs. Actual physical-device use of CAPTURE1B remains untested at this handoff.

## Next device test

Install alongside CAPTURE1A. Reimport the same saved DNG with DNG tools first for an input-controlled comparison, then capture again and retain the render/capture JSON for renderMs and outputSaveTiming. Source exposure and tone must remain fixed while validating speed. Full PNGs transferred without re-encoding are needed for an exact old/new Android pixel comparison.

The original camera transport and capture-report schema/file stem still use CAPTURE1A identifiers; PERF1A appears in the render JSON and CAPTURE1B appears in the app identity. This is intentional, not evidence that an old APK ran.

The live view remains framing-only, not M11-look matched. Capability-based compatibility remains API26+ ARM64 with an exposed supported RAW stream and metadata; universal camera/lens/RAW support is not claimed.

MCC/default-state research and residual CAT42 silicon-exact questions remain separate. Do not brighten the image or retune the firmware-derived tone as a hidden speed correction. Keep no HDR/local tone mapping and the current shared M11 target policy.
