# M11 Standard-A Reference Basis Before CC0

**Status:** STRONG INFERENCE — not yet firmware-proven  
**Date:** 2026-09-08  
**Validation corpus:** 12 genuine Leica M11 DNGs from the Photography Blog review sample set

## Executive finding

The genuine DNG corpus rejects the simple hypothesis that **as-shot white-balanced M11 sensor RGB feeds the fixed R2Y Category-3 CC0 matrix directly**.

Instead, the data strongly supports a two-stage interpretation:

```text
M11 sensor RGB
→ as-shot white balance + interpolated Leica/DNG colour management
→ fixed Standard-A-like reference white-balanced M11 camera basis
→ Category-3 CC0
→ tone
→ Category-13 CC1
→ downstream R2Y/YCC processing
```

The key numerical result is:

| Hypothesis | Mean relative matrix residual after common gain | Max residual |
| --- | ---: | ---: |
| H0: scene WB camera RGB directly → fixed CC0/CC1 | 8.160% | 9.234% |
| H1: scene WB camera RGB → Standard-A reference basis → fixed CC0/CC1 | **0.864%** | **0.877%** |

The H1 residual is tightly clustered across all 12 samples despite scene-white estimates spanning approximately 5115–6043 K and ISO spanning 64–1600.

This is strong structural evidence that the fixed CC matrices are operating on a normalized/reference colour basis rather than raw/as-shot M11 camera RGB.

## Evidence chain

### 1. Genuine M11 DNG metadata

All 12 inspected DNGs contain the same dual-illuminant sensor characterization:

```text
CalibrationIlluminant1 = Standard Light A (17)
CalibrationIlluminant2 = D65 (21)
CameraCalibration1     = identity
CameraCalibration2     = identity
ForwardMatrix1/2       = absent in the inspected DNG metadata
```

`ColorMatrix1`:

```text
 0.5756835938  -0.1333007812  -0.01611328125
-0.607421875    1.538085938    0.4357910156
-0.09838867188  0.1945800781   0.85546875
```

`ColorMatrix2`:

```text
 0.4150390625  -0.07958984375 -0.048828125
-0.5747070312   1.320556641    0.2377929688
-0.1494140625   0.23828125     0.5556640625
```

The embedded profile is named `PROFILE M11`, and its 3×2×1 `ProfileLookTableData` consists only of identity triplets `0 1 1`. Therefore the DNG's embedded look table is not where the in-camera JPEG character is encoded.

### 2. Exact match to prior firmware colour-management findings

Earlier firmware reverse engineering recorded a 132-byte / 33-signed-int32 colour-management structure upstream of R2Y Category-3 CC0.

Its two Q12 matrices were recorded as:

```text
CM1 integers:
 2358  -546   -66
-2488  6300  1785
 -403   797  3504

CM2 integers:
 1700  -326  -200
-2354  5409   974
 -612   976  2276
```

Dividing by 4096 reproduces the genuine M11 DNG `ColorMatrix1` and `ColorMatrix2` **exactly**.

This independently links the DNG sensor characterization to an upstream firmware colour-management stage before the fixed R2Y CC0.

The historical firmware notes also recorded:

- reciprocal-colour-temperature interpolation between those matrices;
- Bradford-type chromatic adaptation;
- pipeline placement before R2Y Category 3.

The exact arithmetic/order/quantization of that firmware consumer is not yet re-extracted, so those implementation details remain OPEN.

## H0 — direct scene white-balanced camera RGB into fixed CC0

Recovered/recorded low-ISO matrices:

```text
CC0 / 512:
 495  -58   63
  10  601 -111
  49 -255  705

CC1 / 512:
1041 -372 -157
-117  630   -1
  -4  -78  595
```

Their combined linear colour transform is:

```text
CC1 × CC0 ≈
 1.92215729  -0.93046188  -0.01453400
-0.19708252   1.47121811  -0.29756927
 0.10068893  -0.75672531   1.63223648
```

Using Adobe-DNG-SDK-compatible no-ForwardMatrix colour semantics, direct comparison of this fixed product with each scene's white-balanced M11 camera→linear-output transform gives 7.525–9.234% residual after allowing one common scalar.

Therefore:

```text
as-shot WB M11 camera RGB → fixed CC0
```

is rejected as the general input-space model.

## H1 — scene basis → fixed Standard-A reference basis → CC0

For each genuine DNG:

1. interpolate the M11 ColorMatrix family using the as-shot neutral / scene white;
2. construct the white-balanced camera→XYZ-D50 PCS transform using Adobe DNG no-ForwardMatrix semantics;
3. construct the same transform at the fixed Standard-A `ColorMatrix1` endpoint;
4. form the colour-basis change:

```text
P_scene_to_A = inverse(T_A) × T_scene
```

where both `T` matrices map white-balanced camera coordinates into the same PCS.

Because both terminate in the same PCS, any common PCS→output transform cancels. The bridge is therefore a camera-basis change, not an sRGB fit.

Then test:

```text
scene WB M11 camera RGB
→ P_scene_to_A
→ fixed CC0
→ fixed CC1
```

against the scene's independently DNG-derived colour transform.

### 12-DNG result

| DNG | ISO | estimated scene CCT | H0 error | H1 error |
| --- | ---: | ---: | ---: | ---: |
| 01 | 125 | ~5514 K | 8.339% | **0.866%** |
| 04 | 64 | ~5767 K | 8.799% | **0.871%** |
| 05 | 1250 | ~5481 K | 8.274% | **0.865%** |
| 10 | 64 | ~5451 K | 8.224% | **0.865%** |
| 14 | 64 | ~5194 K | 7.709% | **0.858%** |
| 20 | 80 | ~5309 K | 7.937% | **0.861%** |
| 24 | 64 | ~5115 K | 7.525% | **0.856%** |
| 31 | 125 | ~5194 K | 7.709% | **0.858%** |
| 34 | 640 | ~6043 K | 9.234% | **0.877%** |
| 37 | 800 | ~5547 K | 8.416% | **0.867%** |
| 38 | 1600 | ~5364 K | 8.046% | **0.863%** |
| 45 | 100 | ~5194 K | 7.709% | **0.858%** |

Aggregate:

```text
H0 mean = 8.1600%
H0 max  = 9.2342%

H1 mean = 0.8638%
H1 max  = 0.8767%

fixed CC product vs Standard-A reference endpoint = 0.7437%
H1 mean common scalar ≈ 1.03716
```

The near-constant H1 residual is particularly important. If this were a scene-specific visual fit, error would be expected to vary substantially with white point. Instead, the basis conversion removes almost all of the daylight/tungsten dependence using only genuine DNG colour metadata plus the fixed recorded firmware matrices.

## Candidate fixed bridge for Xiaomi

The Xiaomi source adapter already terminates in linear scene-referred XYZ D50.

Using the genuine M11 `ColorMatrix1` / Standard-A endpoint and Adobe DNG no-ForwardMatrix semantics, the current candidate fixed bridge from XYZ-D50 PCS into the M11 Standard-A white-balanced reference camera basis is approximately:

```text
XYZ D50 → M11 Standard-A reference WB camera RGB

 1.31879337  -0.14831682  -0.14939568
-0.51395518   1.34347843   0.18430135
-0.27544169   0.50342179   0.92362240
```

This suggests the first Xiaomi offline renderer should test:

```text
Xiaomi RAW
→ Xiaomi native source adapter
→ linear XYZ D50
→ fixed XYZ-D50 → M11 Standard-A reference WB camera basis
→ M11 CC0
→ M11 tone
→ M11 CC1
→ M11 YCC/gamma/chroma candidate chain
```

This is preferable to inventing a visual-fit `XYZ→M11 working RGB` matrix.

## Why this is not yet marked KNOWN

The evidence is strong but incomplete:

- the exact 132-byte firmware structure has not yet been re-extracted from Leica M11-P 2.6.1 in the new repo;
- the historical 2850 K / 6807 K firmware interpolation anchors must be reproduced;
- exact Bradford consumer direction, matrix order, fixed-point scaling and rounding remain unproven;
- the additional raw internal matrix from the 132-byte structure (`[212,-165,-71; -73,676,85; -27,174,285]`) has unresolved semantics and must not be silently folded into the bridge;
- `CC0` and `CC1` values are still recorded prior findings rather than newly re-extracted assets;
- pixel-level DNG→JPEG validation has not yet closed tone/gamma/YCC/output-transfer stages.

Therefore the architectural status is:

```text
KNOWN:
- genuine DNG ColorMatrix1/2 values
- Standard-A + D65 calibration tags
- identity CameraCalibration1/2
- identity embedded M11 look table
- 12-DNG H0/H1 numerical results

RECORDED PRIOR FIRMWARE EVIDENCE:
- upstream 132-byte colour-management structure
- exact matching CM1/CM2 Q12 values
- reciprocal-T interpolation / Bradford-type adaptation
- fixed Category3 CC0 candidate
- low-ISO Category13 CC1 candidate

STRONG INFERENCE:
- CC0 consumes a normalized/reference M11 colour basis equivalent or very close to the Standard-A white-balanced reference-camera basis
- Xiaomi XYZ D50 should bridge into that reference basis before CC0

OPEN:
- exact firmware arithmetic implementing the upstream basis normalization
- extra 132-byte internal matrix semantics
- exact tone/gamma/YCC/output stage order and integer behavior
```

## Next validation

The next useful experiment is pixel-level, not another matrix fit:

1. select 2–4 matched genuine M11 DNG/JPEG pairs;
2. decode the RAW deterministically;
3. apply the H1 reference-basis bridge;
4. run CC0 and one tone hypothesis at a time;
5. compare against the genuine JPEG using spatially corresponding low-frequency colour/luma statistics;
6. vary gamma placement separately;
7. avoid fitting any per-scene matrix or tone offset.

Only after that should the H1 bridge be frozen into the Android renderer.
