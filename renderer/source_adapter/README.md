# Source Adapter

This directory owns **Xiaomi RAW source characterization only**.

Its boundary is deliberately independent of Leica M11 processing:

```text
physical Xiaomi RAW camera RGB
+ DNG/Camera2 metadata
+ live neutral
        ↓
source adapter
        ↓
linear scene-referred XYZ D50
```

The M11 renderer consumes XYZ D50 through a separately validated M11 input-space bridge.

## Current reference implementation

`dng_dual_illuminant.py` provides a target-agnostic dual-illuminant source transform with the corrected DNG matrix conventions recovered during the M9 source-calibration work.

Important invariants:

1. `ColorMatrix1/2` are XYZ → reference-camera matrices and are **not** ForwardMatrix-normalized.
2. `ForwardMatrix1/2` are normalized so camera white `[1,1,1]` maps to D50.
3. Dual-illuminant interpolation is solved from the live neutral in reciprocal-temperature space.
4. `CameraCalibration1/2` participate in both the interpolation solve and final camera→XYZ transform.
5. The live neutral/white-balance diagonal is folded into the returned camera→XYZ-D50 transform.
6. No additional target white-balance matrix belongs downstream merely to compensate for the source adapter.
7. Physical-camera characteristics and physical-camera capture results must correspond to the RAW module actually used.
8. Lens shading is a separate RAW-domain correction, never part of the colour matrix.

## Evidence status

The Python module is now unit-testable and reproduces the previously recorded Xiaomi main ForwardMatrix normalization. It is not yet claimed to be production-final until it is checked against a current Xiaomi 15 Ultra RAW/metadata capture and, ideally, against the Android/Photon implementation on the same metadata vector.

Historical main-camera source values are stored in:

```text
research/xiaomi/xiaomi15ultra_main_native_source_characterization_v1.json
```

Those values are not to be copied to tele, super-tele or ultra-wide. Each physical module needs its own native metadata characterization and regression set.

## What is intentionally absent

- Cobalt matrices/HSM
- Leica M9 matrices/curve02
- M11 CC0/CC1/tone/gamma
- exposure policy
- local tone mapping/HDR
- target output transfer

Those are separate concerns.
