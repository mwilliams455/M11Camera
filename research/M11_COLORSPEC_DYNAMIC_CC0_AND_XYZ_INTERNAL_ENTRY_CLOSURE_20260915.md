# M11 ColorSpec dynamic CC0 and cross-camera XYZ-D50 internal-entry closure

Date: 2026-09-15  
Firmware: Leica M11-P 2.6.1  
Unpacked SHA256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`  
Branch: `work/render1h-cat42yq3a-placement1a`

## Status

Two related seams are now closed strongly enough for reference-code parity work:

1. **Leica-native dynamic CC0 generation** is closed end-to-end from the live AWB gain state through ColorSpec, quantization, frame materialization, and still-R2Y hardware consumption.
2. For a **non-Leica source that has already been characterized and white-balanced into linear XYZ D50**, the clean cross-camera entry into the Leica downstream working domain is the fixed firmware D50-PCS -> internal transform `K`. The Leica M11 sensor-specific ColorSpec must not be applied again to Xiaomi XYZ D50.

`RENDER1H` remains frozen. This document does not authorize an APK or photographic-renderer mutation by itself.

## 1. Dynamic CC0 is the still R2Y CC0

The pointer identity is closed:

- current still-frame global: `0x43433774`
- AAA state object: `0x43379928`
- CM entry: `0x016EB010`
- dynamic CC0 root: `0x43430188 + 0x28`
- frame materialization: `frame + 0x1F8`
- still R2Y dispatcher: `0x0176E75C`

The established live ordering is:

`ColorSpec compute -> dynamic CC0 record -> frame -> R2Y CC0 -> MCC -> gamma`

Therefore the ColorSpec matrix is not DNG-only metadata and is not an extra matrix to prepend to an already-applied CC0.

## 2. Exact floating dynamic-CC0 formula

The successful firmware path is:

```text
CC0_float = K * inverse(C * A) * diag(N)
```

### `N`: live neutral from AWB gains

`cm_fill_parameter` reads signed-16 R/G/B gains from frame offsets `+0x1AC/+0x1AE/+0x1B0`, clamps each to `1..2000`, then stores:

```text
N = [256 / Rgain, 256 / Ggain, 256 / Bgain]
```

### `C`: dual-illuminant Leica ColorMatrix

`R2Y_CC0_CM.bin` is exactly 132 bytes = three 44-byte records. Records 1 and 2 are Q12 calibration matrices:

```text
CM1 raw = [2358,-546,-66,-2488,6300,1785,-403,797,3504]
T1 = 2850 K

CM2 raw = [1700,-326,-200,-2354,5409,974,-612,976,2276]
T2 = 6807 K

CM1 = raw / 4096
CM2 = raw / 4096
```

For the solved white temperature `T`:

```text
T <= 2850  -> C = CM1
T >= 6807  -> C = CM2
otherwise:
  g = (1/T - 1/T2) / (1/T1 - 1/T2)
  C = g*CM1 + (1-g)*CM2
```

Record 3 is a default/seed CC0, not an upstream reference-basis matrix.

### `A`: exact Bradford D50 -> current white adaptation

Firmware matrices:

```text
B =
[ 0.8951,  0.2664, -0.1614
 -0.7502,  1.7135,  0.0367
  0.0389, -0.0685,  1.0296 ]

B^-1 =
[ 0.9869929, -0.1470543,  0.1599627
  0.4323053,  0.5183603,  0.0492912
 -0.0085287,  0.0400428,  0.9684867 ]
```

`MapWhiteMatrix` forms:

```text
A = B^-1 * diag(clamp((B*Wdst)/(B*Wsrc), 0.1, 10.0)) * B
```

with negative transformed-white components clamped to zero and non-positive denominator fallback ratio `10.0`.

### `K`: D50 PCS -> Leica internal working basis

Firmware runtime `0x422247D0`:

```text
K =
[ 1.3460, -0.2556, -0.0511
 -0.5446,  1.5082,  0.0205
  0.0000,  0.0000,  1.2123 ]
```

The numbers match the well-known D50 XYZ -> ROMM/ProPhoto-like linear transform to Leica's stored precision. The firmware evidence, not the external name, is authoritative for implementation.

## 3. NeutralToXY / temperature solve

Firmware starts at D50 xy `(0.3457, 0.3585)` and iterates at most **15 passes**:

1. xy -> temperature/tint
2. interpolate `C`
3. compute `inverse(C) * N`
4. XYZ -> xy
5. stop if `abs(dx)+abs(dy) < 1e-7`

On the final non-converged pass Leica averages the previous and next xy estimates, then recomputes the final temperature/calibration.

The XYZ->xy helper only accepts `X+Y+Z > 1.0`; otherwise it falls back to D50.

### Robertson/Wyszecki-Stiles table

The xy->temperature/tint routine uses 1960 uv, a 31-row `(r,u,v,t)` table, reciprocal temperature scale `1,000,000`, and tint scale `-3000`.

Important Leica-specific value:

```text
r = 325, u = 0.24792, v = 0.34655, t = -2.4681
```

This differs from the commonly published Adobe DNG SDK row whose `u` value is `0.24702`. Firmware parity must retain Leica's `0.24792`.

## 4. Exact CC0 quantization

The floating 3x3 becomes an 11-word / 44-byte signed-int32 record:

- words 0..8: row-major coefficients
- word 9: shift `s`
- word 10: auxiliary scalar; in the live ColorSpec path this is the solved CCT rounded to integer

Shift selection:

```text
for s in [0,1,2]:
  scale = 2^(9-s)
  if round(min(M)*scale) >= -2048 and round(max(M)*scale) <= 2047:
    choose s
    break
else:
  s = 3
```

Coefficient encoding:

```text
q[i] = clamp(round_away_from_zero(M[i] * 2^(9-s)), -2048, 2047)
```

The rounding helper matches C99 `round()` semantics, not ties-to-even.

## 5. Executable parity reference

Research implementation:

- `tools/m11_colorspec_cc0_reference.py`
- tests: `tests/test_m11_colorspec_cc0_reference.py`

The reference covers AWB gain conversion, NeutralToXY, Leica's temperature table, reciprocal-temperature interpolation, Bradford adaptation, matrix inversion/composition, shift selection, C99 rounding, signed-12-bit clamp, and 44-byte record materialization.

Regression example for frame gains `(R,G,B)=(512,256,384)`:

```text
N = (0.5, 1.0, 0.6666666667)
solved CCT ~= 2838.247 K
record = [494,-76,34,-1,665,-213,17,-90,525,0,2838]
```

The full reference CI is green.

## 6. Why M11 ColorSpec must not be applied to Xiaomi XYZ D50

The existing Xiaomi source adapter is deliberately target-agnostic and already ends at **linear scene-referred XYZ D50** with Xiaomi's live neutral / source white balance folded into its camera->XYZ transform.

Leica's dynamic CC0, by contrast, is M11 **camera-space -> Leica internal-space** color management. Its `CM1/CM2`, AWB neutral solve, and Bradford adaptation describe the Leica sensor/reference-camera domain.

Therefore this would be incorrect for Xiaomi:

```text
Xiaomi camera RGB
  -> Xiaomi camera->XYZ D50 + WB
  -> fabricate M11 camera RGB
  -> run M11 sensor ColorSpec CC0 again
```

It would reintroduce Leica sensor calibration after the Xiaomi sensor has already been converted to the common PCS and risks double white/color management.

## 7. Cross-camera internal entry after XYZ D50

For a source already in white-balanced XYZ D50, the firmware-derived downstream entry is simply:

```text
internal = K * XYZ_D50
```

For a source camera matrix `S = camera_to_xyz_d50`:

```text
camera_to_internal = K * S
```

No additional source WB is added at this boundary.

This preserves the architectural separation:

```text
physical Xiaomi sensor characterization / WB
  -> common XYZ D50 PCS
  -> Leica fixed PCS->internal basis K
  -> Leica downstream tone / CC1 / YCC / gamma / chroma
```

## 8. Why the old provisional bridge looked plausible

The frozen research architecture used:

```text
XYZ D50 -> provisional M11 Standard-A reference-camera basis -> historical Category-3 CC0
```

That scaffold was built before the dynamic-CC0 semantics were closed. Independent algebra now shows it was already approximating the direct `K` entry.

Using the historical Category-3 Q9 matrix:

```text
[495,-58,63;
 10,601,-111;
 49,-255,705] / 512
```

and the provisional reference basis, the old combined entry has best scalar fit:

```text
old ~= 0.9654082996 * K
```

with:

- max absolute residual after scalar removal: `< 0.0132`
- RMS residual: `< 0.0075`
- direct `K` relative exposure: about `+0.05079 EV`

This explains why the provisional path produced plausible results: its M11 camera-basis construction and representative CC0 approximately cancel back to the same PCS->internal transform.

## 9. Live Xiaomi 15 Ultra main-sensor check

Current SOURCECAL2A source transform:

```text
S =
[ 1.9584339,   0.10974634,  0.353397
  0.6746988,   0.7578125,   0.03773585
 -0.12001274, -0.45136034,  2.1175075 ]
```

Direct firmware-domain entry:

```text
K*S =
[ 2.469731667134, -0.022913787986,  0.357822445490
 -0.051442632950,  1.073912068766, -0.092137893480
 -0.145491444702, -0.547184140182,  2.567054342250 ]
```

Compared with the old historical Category-3 + provisional-basis entry on the same source:

- best scalar old/direct: `0.9655747553431321`
- direct relative exposure: `+0.0505401371 EV`
- max absolute residual after scalar removal: `< 0.02239`
- RMS residual after scalar removal: `< 0.01197`

Thus the source-specific Xiaomi check agrees with the source-independent algebra: the primary difference is small scale/exposure plus a modest residual color transform, not a wholesale change of working space.

Research implementation/tests:

- `tools/m11_internal_entry_reference.py`
- `tests/test_m11_internal_entry_reference.py`
- workflow `R2A M11 internal entry reference`

## 10. Renderer policy after closure

`RENDER1H` remains frozen for this research branch.

The evidence now supports the following future deliberate integration candidate:

```text
Xiaomi demosaic / camera RGB
  -> Xiaomi source adapter + live neutral WB -> XYZ D50
  -> K -> Leica internal RGB
  -> existing downstream Leica stages
```

A renderer change should be made only after a controlled same-DNG comparison confirms that replacing:

`provisional basis -> static historical CC0`

with:

`direct K`

preserves expected tone/exposure behavior and does not uncover an additional normalization convention at the R2Y boundary.

Do not:

- run M11 sensor ColorSpec on already-white-balanced Xiaomi XYZ D50;
- prepend COLOR132 record 3 as another matrix;
- apply both direct `K` and the old Category-3 CC0;
- add a second source WB;
- enable the unresolved third SRO as part of this change.

## Next validation target

Perform a **diagnostic-only same-DNG A/B render** from the identical Xiaomi XYZ-D50 buffer:

- A: frozen old entry (`provisional basis -> historical/static CC0`)
- B: direct firmware-domain entry (`K`)

Keep all later tone / CC1 / YCC / gamma / chroma stages identical. Record stage histograms, clipping, luma statistics, and output delta. Do not visually tune either path. If the A/B difference matches the predicted ~0.05 EV plus small chromatic residual, direct `K` can be promoted as the cleaner cross-camera entry in a subsequent renderer revision.
