# M11Camera Processing Architecture

## Architectural rule

Keep Xiaomi source correction separate from Leica M11 target rendering.

```text
RAW sensor samples
→ black/white level normalization
→ lens shading / GainMap where required
→ demosaic
→ live white-balance application in the correct source domain
→ Xiaomi physical-camera colour transform
→ linear XYZ D50
→ M11 input-space bridge
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

## Evidence boundaries

The recovered M11 tables are target-process evidence. They do **not** by themselves define how Xiaomi sensor RGB should be fed into the Leica core.

The initial R0 branch therefore concentrates on the interface:

```text
linear XYZ D50 → M11 working/input RGB entering CC0
```

## Runtime target

Once the offline renderer is frozen:

```text
Camera2 RAW_SENSOR
→ JNI / C++ libm11render
→ JPEG
```

The DNG path remains parallel and diagnostic during development rather than becoming the runtime intermediate.
