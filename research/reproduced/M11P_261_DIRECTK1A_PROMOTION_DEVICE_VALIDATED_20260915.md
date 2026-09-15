# M11-P 2.6.1 — DIRECTK1A promotion gate CLOSED

Date: 2026-09-15

Branch: `work/render1h-cat42yq3a-placement1a`

## Decision

Promote the firmware-derived fixed PCS-to-internal matrix `K` as the canonical Xiaomi cross-camera entry:

```text
Xiaomi camera RGB
-> Xiaomi dual-illuminant characterization + AsShotNeutral WB
-> scene-referred XYZ D50
-> Leica firmware PCS_TO_INTERNAL K
-> identity CC0 (bypass old M11 sensor static CC0)
-> frozen RENDER1H tone / CC1 / gamma / CAT42 / orientation / output path
```

Canonical `K`:

```text
[ 1.3460, -0.2556, -0.0511 ]
[-0.5446,  1.5082,  0.0205 ]
[ 0.0000,  0.0000,  1.2123 ]
```

The retired cross-camera detour was:

```text
XYZ D50
-> provisional M11 reference sensor basis
-> selected static M11 sensor CC0
-> downstream renderer
```

That detour is no longer used by the normal promoted workflow.

## Device A/B evidence

All four validations used the same-DNG OLD-vs-DIRECT_K device harness. In every pair:

- same Xiaomi DNG bytes
- same Xiaomi source adapter and live neutral/WB
- same XYZ-D50 boundary
- same ISO-selected CC1 band
- same native RENDER1H downstream math
- no HDR
- no local tone mapping
- no additional downstream source WB
- no extra output OETF
- no third SRO
- native/JNI renderer unchanged for the A/B

### 1. Mixed-light portrait

- source DNG SHA256: `a9c8eeb550366702039575e2fbf8467385f504315a05c0107a292f5e62cbc96e`
- ISO: 347
- predicted DIRECT_K relative exposure: `+0.053060214549156624 EV`
- matrix residual after best scalar: max `0.014986581018468788`, RMS `0.010494974633897538`
- CAT42 pre-clamp outside [0,1]: OLD `0.789101918538%`, DIRECT_K `0.888355573018%`
- photographic result: PASS; no systematic skin/neutral cast or highlight regression observed

### 2. Saturated flowers + dense foliage

- source DNG SHA256: `a849d1d3143c54feb6f67359031fbd13361ce775006a6c810a043cc7a584bdc7`
- ISO: 50
- predicted DIRECT_K relative exposure: `+0.0523022323400304 EV`
- matrix residual after best scalar: max `0.016581705670026863`, RMS `0.010618707139072994`
- CAT42 pre-clamp outside [0,1]: OLD `4.71637248993%`, DIRECT_K `5.21021684011%`
- photographic result: PASS; greens and magenta/pink separation remained stable with no foliage-magenta failure

### 3. High-ISO indoor skin / white / cyan / red

- source DNG SHA256: `77c1e4b05e22af8b6f8d6b95c814a3e52d591123aaa08abc9127128309487ffb`
- ISO: 2960
- predicted DIRECT_K relative exposure: `+0.05177321513564614 EV`
- matrix residual after best scalar: max `0.01892363059381607`, RMS `0.011222958354357151`
- CAT42 pre-clamp outside [0,1]: OLD `5.39629459381%`, DIRECT_K `5.75482050578%`
- photographic result: PASS; no systematic green/yellow skin shift, neutral failure, or deep-shadow hue instability observed

### 4. Overcast sky + dense foliage + deep shadows

- source DNG SHA256: `df8a0e2d52f76409c8c5516daad095ba9db800b4549a9fc327b667d4b2878de8`
- ISO: 50
- predicted DIRECT_K relative exposure: `+0.0517389329656961 EV`
- matrix residual after best scalar: max `0.018973030003896586`, RMS `0.011224522882348525`
- CAT42 pre-clamp outside [0,1]: OLD `5.99410533905%`, DIRECT_K `6.43011728923%`
- photographic result: PASS; cool overcast sky remained neutral and dense foliage did not acquire a magenta/cyan failure

## Interpretation

DIRECT_K consistently introduces only the small brightness/chromatic difference predicted by the matrix comparison. The four scenes cover the failure modes most likely to expose an incorrect cross-camera entry: skin, mixed light, neutral objects, saturated magenta/pink, foliage, deep shadows, high ISO, cyan/blue surfaces, red, and overcast sky.

DIRECT_K does increase out-of-range intermediate values modestly in some scenes, particularly negative blue in dense/dark colors. Across the four validations this did not become a systematic photographic regression. Therefore that difference is recorded as expected internal gamut behavior, not a reason to retain the provisional sensor-basis bridge.

## Promoted implementation

Promotion overlay:

- `tools/apply_render1i_directk1a.py`

Build workflow:

- `.github/workflows/m11-render1i-directk1a.yml`

The normal promoted workflow now computes:

```text
cameraToNativeInput = PCS_TO_INTERNAL_K * source.cameraToXyzD50
```

and clones the selected tables with CC0 replaced by identity. Identity CC0 is mathematically equivalent to disabling the pure 3x3 CC0 stage while preserving the exact frozen JNI/native renderer call and downstream stage topology.

The normal workflow no longer references `M11ReferenceBasisCore.xyzD50ToM11AReferenceWb()` or emits `cameraToM11Reference`.

## CI/build closure

Successful GitHub Actions run:

- run: `34951406201`
- workflow: `M11 RENDER1I DIRECTK1A APK`
- build commit: `c6becb6562f456834d4b0c83131bb5839b1c2ec6`
- result: success

Promotion guardrail proved the native renderer source was byte-identical before and after the DIRECTK1A Java-side entry promotion:

```text
89265792c287e6fdf35b76705a3b3bfe9569c959bde590c7019f6a0928c98ed2  app/src/main/cpp/m11_render_jni.cpp
```

The same hash was recorded before and after the promotion overlay.

APK SHA256:

```text
4cf38ef6c0daa17805b9713522e5a9a3dd9cd497b4122e6a3a1e1d706ba5ed4a
```

Canonical embedded firmware asset SHA256 remains:

```text
54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219
```

Gradle result: `BUILD SUCCESSFUL`, 43 tasks executed.

## Remaining renderer boundary

DIRECTK1A closes the cross-camera entry seam. Do not tune it photographically unless contrary firmware/device evidence appears.

The next renderer research boundary is downstream of this entry and remains the already-recorded RENDER1H limitation: exact Category42 hardware arithmetic, including border equality, handoff quantization, signed rounding, and register +1 scale-code semantics. Those questions should be investigated without reopening the now-closed Xiaomi XYZ-D50 -> Leica internal-space mapping.
