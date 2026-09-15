# M11-P 2.6.1 internal-entry A/B device gate — GATE1A

Date: 2026-09-15
Branch: `work/render1h-cat42yq3a-placement1a`
Build commit: `123bd589295ff2d333dbc8e75812799e65274c14`
Successful workflow run: `34941144736`

## Purpose

Resolve the remaining Xiaomi -> Leica internal-entry seam without modifying the frozen RENDER1H native renderer.

The experiment renders the same Xiaomi DNG twice from the same `camera -> XYZ D50` source-adapter result:

1. **OLD** — the historical frozen entry used by RENDER1H:
   - provisional `M11ReferenceBasisCore.xyzD50ToM11AReferenceWb()`
   - selected static firmware CC0
   - then the frozen downstream renderer.

2. **DIRECT_K** — the firmware-derived cross-camera entry candidate:
   - fixed firmware `PCS_TO_INTERNAL` matrix `K` applied directly to white-balanced XYZ D50
   - CC0 replaced with exact identity, which is equivalent to bypassing the pure 3x3 CC0 multiply
   - then the same frozen downstream renderer.

No M11 sensor ColorSpec / CM1 / CM2 interpolation is applied to Xiaomi data in the DIRECT_K branch. Those matrices belong to the M11 sensor -> Leica internal path, while Xiaomi has already been adapted into the shared XYZ-D50 PCS by `M11SourceAdapterCore`.

## Isolation guarantees

The experiment is Java-only. It does not modify `app/src/main/cpp/m11_render_jni.cpp` or `native/m11_renderer`.

CI hashes after materializing frozen RENDER1H:

- native source before A/B overlay: `89265792c287e6fdf35b76705a3b3bfe9569c959bde590c7019f6a0928c98ed2`
- native source after A/B overlay:  `89265792c287e6fdf35b76705a3b3bfe9569c959bde590c7019f6a0928c98ed2`

The normal RENDER1H action is preserved. The A/B action is separate.

Shared between branches:

- source DNG
- Xiaomi DNG dual-illuminant source adapter
- white-balanced XYZ-D50 boundary
- LibRaw/AHD decode
- selected CC1 band
- tone table
- gamma placement/table
- CAT42/YCC/chroma/output math
- orientation handling
- no HDR
- no local tone mapping
- no extra output OETF
- no additional downstream source WB
- no third SRO

Only the disputed internal-entry transform differs.

## Matrix-level prediction

The Android regression fixture pins the existing Xiaomi sample transform and compares effective OLD vs DIRECT_K entry matrices.

Current exact branch constants predict:

- best scalar OLD -> DIRECT_K: `0.9655719830436862`
- DIRECT_K relative exposure: `+0.050540137 EV`
- max absolute residual after removing scalar: `0.0223860008032`
- RMS residual after removing scalar: `0.0119681547138`

This means the two paths are close to a global scalar but not identical. The device A/B is required because the residual is chromatic and downstream nonlinear stages can make a small matrix difference photographically meaningful.

## CI result

Workflow: `M11 internal-entry OLD vs DIRECT_K A/B APK`
Run: `34941144736`
Conclusion: **success**

Passed:

- canonical firmware asset validation
- frozen rawpy/LibRaw oracle validation
- synthetic RAW/AHD parity assets
- frozen RENDER1H materialization
- A/B overlay integrity gates
- photographic-boundary audit
- Java unit tests
- arm64-v8a native build
- APK assembly
- APK content audit
- embedded firmware-asset hash audit
- build-evidence upload
- APK artifact upload

Built APK SHA-256:

`0a09906bb5db105e842c35f1f2b4123cdc01b09d2eabb840482f7859ffde8c8b`

GitHub artifact:

`M11Cam-RENDER1H-INTERNAL-ENTRY-AB`

## Device validation procedure

Use a Xiaomi 15 Ultra main-camera DNG with ordinary exposure and valid DNG source matrices / `AsShotNeutral`.

In the APK choose the dedicated **internal-entry OLD vs DIRECT_K A/B** action and select the DNG once.

The app saves six primary files:

- `..._OLD.png`
- `..._OLD.jpg`
- `..._OLD.json`
- `..._DIRECT_K.png`
- `..._DIRECT_K.jpg`
- `..._DIRECT_K.json`

The two JSON files should report the same source DNG SHA-256, ISO/CC1 band, source-adapter transform, dimensions and downstream configuration.

## Promotion rule

Do **not** promote DIRECT_K from this build result alone.

Promotion requires real-DNG photographic evidence showing that DIRECT_K improves Leica/M11 behavior without introducing a systematic color cast, tonal regression, clipping/headroom regression, or scene-dependent instability.

Evaluate primarily:

- neutral / near-neutral objects
- foliage and sky separation
- skin/flesh rendering if present
- tungsten/indoor neutrals
- deep-shadow hue stability
- highlight color and rolloff
- overall M11-like color separation versus the OLD branch

Brightness alone should not decide the result because the matrix prediction already indicates about +0.0505 EV direct-K shift.

If DIRECT_K is consistently superior, the next engineering step is a minimal promoted entry change: replace the provisional basis + static CC0 pair with `K` at the XYZ-D50 boundary, while leaving the downstream frozen renderer unchanged. If results are mixed, keep RENDER1H frozen and investigate the residual/domain placement rather than tuning around the A/B photographically.
