# Xiaomi 15 Ultra Native Source Adapter — Reuse Contract

**Status:** R0 architecture/evidence note  
**Target project:** M11Camera  
**Source lineage inspected:** `mwilliams455/M9Camera_refresh`, branch `m9sourcecal2a-nativeprospective1a-reviewfix1`

## Why this is reusable

The M9 source-calibration work intentionally separated **Xiaomi source characterization** from the **Leica target renderer**. That separation is exactly what M11Camera needs.

The reusable contract is:

```text
Xiaomi physical RAW sensor samples
+ physical CameraCharacteristics
+ matching physical CaptureResult
+ live SENSOR_NEUTRAL_COLOR_POINT
        ↓
DNG/Camera2 dual-illuminant source characterization
        ↓
linear scene-referred XYZ D50
        ↓
M11-specific target input bridge   [separate research problem]
```

No Cobalt profile, Leica target matrix, Leica tone curve, Leica HSM, or M9 exposure logic belongs inside this source adapter.

## Required Camera2 / DNG metadata

For the selected **physical** camera module, the reusable source model consumes:

- `SENSOR_REFERENCE_ILLUMINANT1`
- `SENSOR_REFERENCE_ILLUMINANT2`
- `SENSOR_CALIBRATION_TRANSFORM1`
- `SENSOR_CALIBRATION_TRANSFORM2`
- `SENSOR_COLOR_TRANSFORM1`
- `SENSOR_COLOR_TRANSFORM2`
- `SENSOR_FORWARD_MATRIX1`
- `SENSOR_FORWARD_MATRIX2`
- live `CaptureResult.SENSOR_NEUTRAL_COLOR_POINT`

For a logical multi-camera device, the physical `CaptureResult` must be resolved from `TotalCaptureResult.getPhysicalCameraTotalResults()` / the pre-Android-S equivalent when a physical module is requested. Using the logical/top-level result without proving it corresponds to the physical RAW module is not sufficient.

## Matrix convention that must remain frozen

The earlier source-calibration audit caught an important convention bug:

> DNG `ColorMatrix1/2` are **XYZ → reference-camera** transforms and must be preserved as supplied.

Do **not** apply the ForwardMatrix row-normalization helper to `ColorMatrix1/2`.

The corrected route is:

```text
ColorMatrix1/2        → keep unmodified
ForwardMatrix1/2      → normalize using the renderer's DNG ForwardMatrix convention
CameraCalibration1/2  → retain in the DNG dual-illuminant solve
As-shot/live neutral  → use in interpolation + white-balance-aware transform
```

In the Photon-derived implementation, the corrected interpolation call uses the original `cm1/cm2`, while the camera-to-XYZ-D50 calculation uses the normalized ForwardMatrices plus calibration transforms, neutral and interpolation factor.

## Interchange space

The source adapter's output contract should be:

```text
linear scene-referred XYZ D50
```

The M9 native prospective experiment explicitly labeled the source scene space as `XYZ_D50`, recorded that the native transform already included the live neutral/white-balance solve, and applied **no additional white-balance diagonal** afterward.

For M11Camera, retain the same source-space contract and replace only the downstream target bridge.

## Main-camera evidence already available

A 12-DNG Xiaomi 15 Ultra main-camera audit found the following metadata stable across the inspected captures, while `AsShotNeutral` varied by scene:

- Calibration Illuminant 1: D65 (`21`)
- Calibration Illuminant 2: Standard Light A (`17`)
- CFA: RGGB
- approximate black level: 64
- white level: 1023

Recorded native `ColorMatrix` values:

### D65

```text
 1.2812500  -0.4843750  -0.2265625
-0.5859375   1.5937500   0.1406250
-0.0468750   0.1796875   0.7031250
```

### Standard Light A

```text
 0.8359375  -0.1718750  -0.1328125
-0.4687500   1.3984375   0.0468750
-0.0859375   0.3359375   0.4062500
```

Recorded raw ForwardMatrix for both illuminants in that corpus:

```text
 0.6328125   0.1093750   0.2187500
 0.2187500   0.7578125   0.0234375
-0.0390625  -0.4531250   1.3203125
```

These numbers are **main-camera evidence**, not universal constants for the other three rear modules. Each physical camera must be characterized independently.

## Lens shading is a separate stage

The later M9 prospective review made an important separation explicit:

```text
RAW black subtraction
→ optional Camera2 LensShadingMap correction
→ preserve linear headroom
→ demosaic
→ source colour transform
```

A combined source-colour + lens-shading A/B was considered confounded until a source-only control existed. M11Camera should preserve that discipline.

For the first M11 main-camera renderer:

1. validate source colour with lens shading disabled/identity first;
2. add Camera2 lens shading as a separately switchable RAW-domain stage;
3. preserve headroom rather than clipping map gains >1 during U16 transport;
4. never bake lens shading into the sensor→XYZ matrix.

## Explicit exclusions from M9

Do **not** port these M9-specific elements into the M11 source adapter:

- M9 target ColorMatrix A/D65;
- M9 `curve02`;
- M9 HSM/profile creative colour;
- TC20 exposure decisions;
- edge-placement policies;
- M9 tungsten guard/compression;
- M9 output transfer;
- any Cobalt target/source mixture.

They belong to a different target renderer or to historical experiments.

## M11Camera source-adapter API contract

The eventual implementation should expose something equivalent to:

```text
SourceFrame {
    linear_bayer_or_demosaiced_camera_rgb
    physical_camera_id
    black_level[4]
    white_level
    cfa_pattern
    color_matrix_1/2
    camera_calibration_1/2
    forward_matrix_1/2
    calibration_illuminant_1/2
    neutral_color_point
    optional_lens_shading_map
}

SourceTransformResult {
    linear_xyz_d50
    interpolation_factor
    scene_white_xy
    estimated_cct
    physical_camera_match_verified
    diagnostics
}
```

The `M11 expected input bridge` consumes `linear_xyz_d50`; it must not reach back into Xiaomi metadata or Cobalt assets.

## R0 implementation gates

Before this becomes active rendering code:

- [ ] recover or reimplement the exact DNG dual-illuminant interpolation math used by the corrected Photon `Converter` path;
- [ ] unit-test ColorMatrix direction with synthetic matrices so accidental inversion/row normalization fails loudly;
- [ ] unit-test physical-camera result association;
- [ ] capture a current Xiaomi 15 Ultra main RAW + metadata sidecar and confirm the historical matrix set still matches;
- [ ] produce a source-only XYZ-D50 diagnostic render with no M11 stages;
- [ ] only then connect XYZ D50 to the M11 input-space bridge.
