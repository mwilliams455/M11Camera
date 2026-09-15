# M11 internal-entry A/B harness ready — 2026-09-15

## Status

The firmware investigation has closed the cross-camera entry architecture far enough to run one bounded photographic validation without changing the frozen renderer.

The research-only A/B harness is:

`tools/compare_m11_internal_entry_ab.py`

CI validation:

- workflow: `R2A M11 internal entry A/B`
- run: `34939648953`
- result: **success**
- renderer mutation: **none**

## Question under test

Both branches start from the **same linear, white-balanced XYZ D50 buffer** produced by the Xiaomi DNG source adapter.

### A — frozen historical bridge

```text
XYZ D50
-> provisional M11 reference-basis bridge
-> historical/static Category-3 CC0
-> shared downstream Leica stages
```

### B — firmware-domain direct entry

```text
XYZ D50
-> fixed firmware PCS_TO_INTERNAL matrix K
-> NO additional CC0
-> shared downstream Leica stages
```

The shared downstream stages are unchanged:

```text
tone -> CC1 -> YCC -> gamma(Y) -> mode chroma -> inverse YCC -> clamp
```

This is deliberately not a new renderer revision. It is a diagnostic comparison around one disputed seam.

## Why direct K is the candidate

Firmware ColorSpec closure shows that the live Leica sensor path generates the hardware CC0 which maps the current camera/white state into Leica's internal working domain. Once a different camera has already been characterized and white-balanced into a common XYZ D50 PCS, re-running M11 sensor-specific ColorSpec would be a second sensor calibration and a second WB/color-management operation.

The fixed firmware matrix `K` is the closed PCS-D50 -> Leica internal-space conversion:

```text
[ 1.3460, -0.2556, -0.0511 ]
[-0.5446,  1.5082,  0.0205 ]
[ 0.0000,  0.0000,  1.2123 ]
```

Therefore the clean cross-camera candidate is:

```text
Xiaomi camera RGB
-> Xiaomi source calibration + live neutral WB
-> XYZ D50
-> K
-> Leica downstream rendering
```

not:

```text
XYZ D50
-> synthetic M11 sensor/reference basis
-> historical M11 CC0
```

and not:

```text
XYZ D50
-> M11 ColorSpec again
```

## Harness diagnostics

The A/B records, for both branches:

- post-entry/internal stage statistics;
- post-tone statistics;
- post-CC1 statistics;
- YCC statistics;
- post-gamma YCC statistics;
- post-chroma YCC statistics;
- pre-clamp RGB statistics;
- final output RGB statistics;
- 64-bin channel histograms with under/overflow counts;
- luma mean/min/p01/p50/p95/p99/max;
- below-zero and above-one fractions;
- clipping-related pixel fractions;
- branch-to-branch signed and absolute deltas;
- 8-bit-code delta fractions;
- PSNR/MSE diagnostic;
- full-frame 8-bit delta statistics;
- old and direct-K JPEGs.

The harness also independently executes the canonical reference renderer on both branches and fails if its explicit stage composition differs by more than `1e-12` from the canonical renderer result.

## Expected matrix-level result

Previous closure predicts that the old provisional-basis + historical-CC0 composite is almost a scalar version of direct K.

For the recorded Xiaomi source transform, direct K is expected to be approximately:

```text
+0.0505 EV
```

relative to the old entry, plus a small chromatic residual.

The real-DNG A/B is intended to test whether the downstream nonlinear stages preserve that bounded difference or whether clipping/tone/gamma makes the practical difference larger.

## Real-DNG gate

The historical real Xiaomi main DNG used for RAW/AHD validation was:

```text
IMG_20260910_062107.dng
size:   25,195,908 bytes
SHA256: 5f743887ab4dafba76ffe8d865ea40622bd2737fb41b6a2d9bc40c1f11f08e2a
```

At the time this harness was completed, the raw DNG itself was no longer present in the accessible File Library, Dropbox, or repository. Only its validation record remains. Therefore no claim is made that a real photographic A/B has already been completed.

When that exact DNG is available again, run:

```bash
python tools/compare_m11_internal_entry_ab.py \
  IMG_20260910_062107.dng \
  --mode standard \
  --data-dir /path/to/M11P_color_forensics_v0.3 \
  --out-dir work/internal_entry_ab_062107 \
  --expected-dng-sha256 5f743887ab4dafba76ffe8d865ea40622bd2737fb41b6a2d9bc40c1f11f08e2a
```

A new Xiaomi 15 Ultra main-camera DNG is also valid for the experiment; omit the historical SHA gate and retain the generated DNG/source metadata in the result.

## Promotion rule

Do **not** change RENDER1H yet.

Promote direct K only after a real-DNG A/B shows:

1. no structural break or unexpected clipping increase;
2. output change broadly consistent with the predicted small exposure/chromatic residual;
3. no second WB or ColorSpec application;
4. identical downstream Leica stages;
5. no HDR, local tone mapping, third SRO, or visual tuning introduced.

If those conditions hold, the next renderer revision should remove the provisional M11 reference-basis bridge and static historical CC0 as a pair and replace them with direct `K` from the Xiaomi XYZ-D50 boundary. The two old stages must not remain active behind direct K.
