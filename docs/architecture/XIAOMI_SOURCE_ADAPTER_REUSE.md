# Xiaomi 15 Ultra Native Source Adapter — Reuse Contract

**Status:** R3 source boundary validated on current main-camera metadata  
**Target project:** M11Camera  
**Source lineage:** `mwilliams455/M9Camera_refresh` SOURCECAL2A + current M11Camera revalidation

## Why this is reusable

The M9 source-calibration work intentionally separated **Xiaomi source characterization** from the **Leica target renderer**. That separation is exactly what M11Camera needs.

The reusable contract is:

```text
Xiaomi physical RAW sensor samples
+ physical CameraCharacteristics / DNG metadata
+ matching physical CaptureResult
+ live SENSOR_NEUTRAL_COLOR_POINT / AsShotNeutral
        ↓
DNG/Camera2 dual-illuminant source characterization
        ↓
linear scene-referred XYZ D50
        ↓
M11-specific target input bridge
```

No Cobalt profile, Leica target matrix, Leica tone curve, Leica HSM, M9 exposure logic, HDR or local tone mapping belongs inside this source adapter.

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

The corresponding DNG route consumes `CalibrationIlluminant1/2`, `CameraCalibration1/2`, `ColorMatrix1/2`, `ForwardMatrix1/2` and `AsShotNeutral`.

For a logical multi-camera device, the physical `CaptureResult` must be resolved from the physical-camera result set when a physical module is requested. Using the logical/top-level result without proving it corresponds to the physical RAW module is not sufficient.

## Matrix convention that must remain frozen

The earlier source-calibration audit caught an important convention bug:

> DNG `ColorMatrix1/2` are **XYZ → reference-camera** transforms and must be preserved as supplied.

Do **not** apply the ForwardMatrix row-normalization helper to `ColorMatrix1/2`.

The corrected route is:

```text
ColorMatrix1/2        → keep unmodified
ForwardMatrix1/2      → normalize using the DNG ForwardMatrix convention
CameraCalibration1/2  → retain in the DNG dual-illuminant solve
As-shot/live neutral  → use in interpolation + white-balance-aware transform
```

The corrected interpolation call uses the original `cm1/cm2`, while the camera-to-XYZ-D50 calculation uses the normalized ForwardMatrices plus calibration transforms, neutral and interpolation factor.

## Slot association is semantic, not cosmetic

Android Camera2 defines transform slot 1 as belonging to `SENSOR_REFERENCE_ILLUMINANT1` and transform slot 2 as belonging to `SENSOR_REFERENCE_ILLUMINANT2`. `DngCreator` preserves this association when writing the corresponding DNG `*1` and `*2` tags.

A 2026-09-09 live main-camera SOURCECAL2A sidecar exposed a historical naming error in the earlier static audit: the two numerical Xiaomi ColorMatrix values were stable, but their human-readable D65/A labels had been reversed.

The corrected main-camera slot association is:

- Illuminant 1: D65 (`21`) → `ColorMatrix1`
- Illuminant 2: Standard Light A (`17`) → `ColorMatrix2`

This correction changes **semantic labels only**, not the recovered matrix numbers.

## Interchange space

The source adapter output contract is:

```text
linear scene-referred XYZ D50
```

The native SOURCECAL2A path records that its transform already includes the live neutral/white-balance solve. Therefore the M11 path applies **no additional Xiaomi white-balance diagonal** afterward.

The M11-specific target input bridge starts only after XYZ D50.

## Current main-camera evidence

Current live validation was captured from requested physical camera ID `2`, with the capture-result camera ID also `2`, focal length about `8.72 mm`, aperture about `f/1.63`, CFA code `0` (RGGB in the project mapping), black level `[64,64,64,64]` and white level `1023`.

### Slot 1 — D65 (`21`) / ColorMatrix1

```text
 0.8359375  -0.1718750  -0.1328125
-0.4687500   1.3984375   0.0468750
-0.0859375   0.3359375   0.4062500
```

### Slot 2 — Standard Light A (`17`) / ColorMatrix2

```text
 1.2812500  -0.4843750  -0.2265625
-0.5859375   1.5937500   0.1406250
-0.0468750   0.1796875   0.7031250
```

### CameraCalibration1/2 — identical in current live evidence

```text
1.03125  0        0
0        1        0
0        0        1.015625
```

### ForwardMatrix1/2 — identical in current live evidence

```text
 0.6328125   0.1093750   0.2187500
 0.2187500   0.7578125   0.0234375
-0.0390625  -0.4531250   1.3203125
```

The current live evidence is recorded in:

```text
research/xiaomi/xiaomi15ultra_main_sourcecal_live_20260909.json
```

The consolidated characterization is:

```text
research/xiaomi/xiaomi15ultra_main_native_source_characterization_v1.json
```

These numbers are **main-camera evidence**, not universal constants for the tele, super-tele or ultra-wide modules. Each physical camera must be characterized independently.

## Live numerical parity gate — CLOSED for main source calibration

The M11 Python source adapter now has a direct regression against the 2026-09-09 device-side SOURCECAL2A result.

For live neutral:

```text
[0.32421875, 1.0, 0.62109375]
```

the device-side corrected SOURCECAL2A path reports interpolation factor:

```text
0.00006103515625
```

and camera → XYZ D50:

```text
 1.9584339   0.10974634   0.3533970
 0.6746988   0.75781250   0.03773585
-0.12001274 -0.45136034   2.1175075
```

`renderer/source_adapter/dng_dual_illuminant.py` reproduces that factor exactly at the recorded precision and the matrix within floating-point tolerance. The parity test is locked in `tests/test_render_xiaomi_m11_controlled.py`.

Because `ForwardMatrix1 == ForwardMatrix2` and `CameraCalibration1 == CameraCalibration2` on the current main sensor, the corrected D65/A ColorMatrix slot naming does not change this final transform. It does correct the interpolation/CCT interpretation and is essential for any future sensor whose two forward/calibration endpoints differ.

## Lens shading remains a separate stage

The separation remains:

```text
RAW black subtraction
→ optional Camera2 LensShadingMap correction
→ preserve linear headroom
→ demosaic
→ source colour transform
```

For the first M11 main-camera renderer:

1. validate source colour with lens shading disabled/identity first;
2. add Camera2 lens shading later as a separately switchable RAW-domain stage;
3. preserve headroom rather than clipping map gains >1 during U16 transport;
4. never bake lens shading into the sensor→XYZ matrix.

The current controlled offline runner deliberately does not invent a lens-shading stage from incomplete DNG evidence.

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

## Current M11Camera source-adapter contract

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

The M11 expected-input bridge consumes `linear_xyz_d50`; it must not reach back into Xiaomi metadata or Cobalt assets.

## Implementation gates after R3

Completed for main source calibration:

- [x] reimplement corrected Photon/DNG dual-illuminant interpolation math;
- [x] preserve ColorMatrix direction and prevent ForwardMatrix normalization of ColorMatrix;
- [x] obtain a current Xiaomi main-camera physical-result sidecar with requested/capture camera-ID match;
- [x] confirm the numerical static matrix set remains stable;
- [x] correct the historical D65/A semantic slot labels;
- [x] reproduce the live device-side SOURCECAL2A interpolation factor and camera→XYZ-D50 matrix in Python;
- [x] connect XYZ D50 to the separate M11 input-space bridge in a controlled runner.

Still open for photographic/device validation:

- [ ] execute the controlled runner on an actual current Xiaomi main-sensor DNG with the validated firmware table directory;
- [ ] produce source-only and full M11 diagnostics from that DNG;
- [ ] compare daylight / overcast / indoor-neutral / tungsten / skin / saturated / high-DR-no-HDR scenes;
- [ ] independently characterize tele, super-tele and ultra-wide before enabling them;
- [ ] add lens shading only as a separately validated RAW-domain stage if required.
