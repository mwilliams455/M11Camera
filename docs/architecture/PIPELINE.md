# M11Camera Processing Architecture

## Architectural rule

Keep Xiaomi source correction separate from Leica M11 target rendering.

Current working architecture:

```text
RAW sensor samples
→ black/white level normalization
→ lens shading / GainMap where required
→ demosaic
→ Xiaomi physical-camera source characterization + live neutral
→ linear scene-referred XYZ D50
→ M11 Standard-A reference WB camera-basis bridge   [STRONG INFERENCE]
→ M11 CC0
→ M11 tone
→ M11 CC1
→ M11 Y/Cb/Cr-like stage
→ M11 gamma candidate
→ M11 mode chroma
→ inverse Y/Cb/Cr
→ output-gamut / transfer stage
→ JPEG
```

## First supported configuration

```text
Xiaomi 15 Ultra main camera
M11 Standard
single RAW frame
full-resolution sRGB JPEG
optional development DNG
```

## Source-adapter boundary

The Xiaomi source adapter terminates at:

```text
linear scene-referred XYZ D50
```

It must remain independent of Leica target colour and must not depend on Cobalt.

The currently validated source-side rules include:

- use the physical camera's Camera2/DNG characterization;
- preserve DNG `ColorMatrix` semantics rather than ForwardMatrix-normalizing it;
- fold the live neutral into the dual-illuminant source transform;
- treat lens shading as a separate RAW-domain correction;
- preserve linear headroom.

## M11 input-space bridge

The original R0 interface was intentionally left open as:

```text
linear XYZ D50 → unknown M11 working/input RGB entering CC0
```

Genuine M11 DNG validation has now narrowed this substantially.

Twelve genuine M11 DNGs reject direct as-shot white-balanced sensor RGB as the input to the fixed recorded CC0/CC1 pair: the mean colour-matrix residual after one common gain scalar is approximately **8.16%**.

If each scene is first converted into the fixed Standard-A white-balanced M11 reference-camera basis implied by `ColorMatrix1`, the mean residual drops to approximately **0.864%**, with a maximum of approximately **0.877%** across all 12 samples.

The firmware research had independently recorded an upstream 132-byte colour-management structure before R2Y Category 3 whose Q12 CM1/CM2 matrices exactly equal the genuine DNG `ColorMatrix1/2` values. This makes the reference-basis interpretation structurally plausible rather than a visual fit.

Current candidate fixed PCS bridge:

```text
XYZ D50 → M11 Standard-A reference WB camera RGB

 1.31879337  -0.14831682  -0.14939568
-0.51395518   1.34347843   0.18430135
-0.27544169   0.50342179   0.92362240
```

This matrix is a **reference implementation candidate**, not yet a claim of exact firmware arithmetic. The exact firmware upstream interpolation, Bradford direction, fixed-point scaling, rounding, and the additional raw internal matrix in the 132-byte structure still require re-extraction/consumer tracing.

See:

```text
docs/research/M11_STANDARD_A_REFERENCE_BASIS_HYPOTHESIS.md
```

## Target-renderer evidence boundary

The recovered M11 tables and recorded firmware constants are target-process evidence. They do not authorize direct application of CC0/CC1 to Xiaomi sensor RGB.

The current intended boundary is therefore:

```text
Xiaomi source RGB
→ Xiaomi source adapter
→ XYZ D50
→ M11 reference-camera basis bridge
→ M11 target renderer
```

## Exposure boundary

Exposure/metering is intentionally separate from the renderer. Do not import M9 TC20 or old LUT-era EV preferences into M11 capture policy until M11 exposure behavior is investigated independently.

## Runtime target

Once the offline renderer is structurally validated:

```text
Camera2 RAW_SENSOR
→ JNI / C++ libm11render
→ full-resolution JPEG

same RAW
→ DngCreator
→ archival/development DNG
```

The DNG path remains parallel and diagnostic rather than becoming the runtime intermediate.
