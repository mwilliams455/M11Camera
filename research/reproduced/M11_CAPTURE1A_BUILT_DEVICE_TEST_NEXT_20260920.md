# M11 CAPTURE1A — built, first physical-device capture test next

Date: 2026-09-20.

## Build identity

Baseline: portable RENDER1J, `d89157bc8e5c1e154da8c22bbffa74089663f76a`.
New branch: `work/capture1a-portable`.
Build/code commit: `542f7037b4e7410d5ddce0370b94005f72070f4d`.
Workflow: `.github/workflows/m11-capture1a.yml`.
Successful run: `35503396569`; job `106059014985`.
APK artifact: `10602253821`. Evidence artifact: `10603166489`.

APK version: `0.2.0-capture1a`; versionCode 15.
Application ID: `com.m11.diagnostic.capture1a`.
Label: `M11 Capture1A`; launcher: `com.m11.diagnostic.M11CaptureActivity`.
Separate application ID permits side-by-side installation with RENDER1J.
Android API26+, arm64-v8a; compatible RAW capture stream and metadata required.

Downloaded APK: 3,787,582 bytes.
SHA-256: `5ac1725fc93b07ff60e746266a8b9ab0ca213408a89ed590903a12ef7e6a661a`.
APK ZIP digest: `6f6219af8208986cc0c91c0dc4ced0d5d192ac625c11c7bbcf3d1f8e4b92f5ab`.
Evidence ZIP digest: `0a5480f0e6600de7fb7c9aa87c36c2d19bdfb04f4a4fafe6d4d722865f75f1fb`.
Both ZIP digests and the APK's CI hash were independently checked after download.

## Implemented capture flow

The new Camera2 shell captures one RAW_SENSOR frame, pairs the image and source result by exact positive sensor timestamp, creates a DNG with that source's characteristics and same-frame result, closes the image, and automatically sends the saved DNG to the existing portable M11 Standard workflow. No manual DNG selection is needed for this route.

The original DNG is published and its copy hash checked. Output is original DNG, JPEG quality98, PNG, renderer JSON and separate capture JSON. A reduced display copy of the saved JPEG replaces the live framing view; saved image dimensions/quality are not reduced for that display.

The UI provides source selection, Take M11 photo, a Camera2 AE compensation slider, source ISO/shutter readout, Reopen, Share last set and DNG tools. Tap the completed image to return to framing. One capture/render is allowed at a time. EV changes the sensor exposure request, not post-render brightness.

Physical source selection is capability-based, not a manufacturer/model whitelist. Logical groups use explicitly targeted physical output surfaces and the corresponding physical result. Missing physical metadata fails rather than borrowing the logical camera's matrices. The RAW stream preference is the largest advertised stream up to16MP, otherwise the smallest advertised RAW stream; it does not resize RAW pixels or assume 4096x3072.

The pairing logic retains at most two unmatched images and closes stale, duplicate/replaced, cancelled and mismatched inputs. Camera/session/surface ownership is serialized. Rendering receives a DNG file, never an owned camera Image. Handled failures attempt a diagnostic JSON and retain the original RAW when available.

## Reuse boundary

Reviewed M9's physical sensor contract at `f5ce9888f62e3f6dced298a0edaf537005fc7d5b` and Monochrome's physical-ISO patch at `32658cddf7b154b6fbd29814250c2c6aa1887822`.

This is a small Camera2 shell inside M11, not a transplant of the complete M9/Photon app. It applies the physical-source metadata authority rule without importing M9 target processing, Photon exposure allocation or normalized-ISO UI values.

## Frozen rendering evidence

Eleven existing RAW/source/target/bridge/output files are hash-identical before and after the capture overlay and after the Android build. The source/RAW/native rendering block inside M11RenderWorkflow is also source-text identical; only the shared execution wrapper, capture diagnostics and filename handling were extended.

More strongly, the new APK's native `libm11rawjni.so` is byte-for-byte identical to the previous RENDER1J APK's library:
`d3c3f7fd0614dcbef5c3e20e11ee17547c163571e56a59a9f4b53a6ce31adf98`.

Embedded target asset remains23,150 bytes, SHA-256:
`54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219`.

Preserve DIRECTK1A, identity CC0, frozen downstream, inactive Cat25 and Cat42 code/512 with hardware-exact=false. No guessed MCC, M9 colour/tone, app HDR or new local tone mapping was added.

## Executed validation

- 33 existing JVM/JUnit tests passed: zero failures/errors/skips.
- 89 new capture-core assertions passed locally and in CI: both image/result arrival orders, timestamps, stale callbacks, cancellation, image ownership, dimensions and orientation.
- Existing prerequisite tests passed: 37 native capability assertions with sanitizers, 87 source-metadata assertions, 16 synthetic decoder fixtures.
- Android compile, assembly, launcher check and APK signature-v2 verification passed.
- Downloaded artifact hashes, binary manifest identity, embedded asset and native library comparison passed.
- All seven source/test payload files matched the downloaded CI versions.

These are host/JVM/build/binary checks. No physical-device launch, RAW capture, repeated shooting or real captured-DNG reimport pixel-parity test was performed. That is the next evidence gate, not a completed result.

## Deliberate limits and device test

The live feed is explicitly labelled framing-only, NOT M11-look-matched. The M11 result is shown after capture. There are no manual ISO/shutter dials or burst mode in this milestone. AF/AE/AWB waits are bounded; slow/unsettled 3A is recorded. This is not recovered M11 metering.

RAW exposure, metadata, preview transform, stream compatibility, memory use and successive capture need device validation. Manufacturer-independent does not guarantee every camera/lens is exposed or supports the requested stream combination. Vendor RAW preprocessing and optical shading are not newly corrected by this work.

On Android10/API29+ DNG/JPEG/PNG go to Pictures/M11Camera and JSON to Download/M11Camera. Share last set includes original DNG, JPEG and both JSON files, not the PNG. API26-28 uses app-scoped storage; the public-path status wording and content-URI share convenience are aimed at API29+ and are not complete older-Android sharing support.

First test: install alongside RENDER1J, allow Camera, choose one rear RAW source, start at EV0, take one photograph and allow rendering to finish in the foreground. Tap the result, take a second photograph, then share the last set. Retain the original DNG for a same-source reimport through RENDER1J. If opening fails, select another advertised source or use Reopen and retain the error JSON.

Delivered continuation files: `M11_PROJECT_HANDOFF_v1_12_CAPTURE1A_BUILT_DEVICE_TEST_NEXT_20260920.md`, `M11_CAPTURE1A_verification.json`, and `M11_CAPTURE1A_SOURCE_TESTS_20260920.zip`.
