# R2 Firmware Access and Gamma Diagnostic Status

**Date:** 2026-09-08  
**Branch:** `research/m11-r0-evidence-input-space`

## Dropbox firmware evidence now confirmed

The connected Dropbox folder:

```text
/chatgpt/m11/firmware
```

contains:

```text
LEICA_M11-P_2.6.1.FW
M11P_2.6.1_extracted.tar.gz
```

Observed Dropbox metadata:

| File | Size | Modified |
| --- | ---: | --- |
| `LEICA_M11-P_2.6.1.FW` | 63,621,633 bytes | 2026-09-08T05:11:34Z |
| `M11P_2.6.1_extracted.tar.gz` | 47,825,011 bytes | 2026-09-08T05:11:33Z |

Dropbox content hashes reported by the connector:

```text
LEICA_M11-P_2.6.1.FW
  a279d8bb87720ed9d02b3c36b3b670917c3972a0e09616fec95b47c8d970573b

M11P_2.6.1_extracted.tar.gz
  3ec4631a0e545fa91b9e5c3a778e8db36d09f550acbe869a390b34af58b42a23
```

These are Dropbox content hashes, not SHA-256 file digests, and must not be mislabeled as such.

The current Dropbox connector can authenticate and generate temporary direct-download URLs for these files, but the analysis container cannot resolve Dropbox's download host. The temporary URL must not be committed to this public repository. Therefore byte-level firmware extraction remains blocked only by runtime handoff, not by missing source evidence.

The preferred byte-level input is the already-extracted archive because it avoids repeating decompression before inspecting the named pipeline assets.

## Priority assets once archive bytes are locally mounted

Immediately inventory and hash:

```text
img/data/r2y.bin
img/data/R2Y_CC0_CM.bin
img/data/R2Y_TF_REMAPPING_CM.bin
```

Then enumerate neighboring `img/data` assets containing names such as:

```text
R2Y
Y2R
TF
GAMMA
GAM
TONE
```

The first reproducibility gates remain:

1. reproduce recorded Category-3 CC0 values;
2. reproduce low-ISO Category-13 CC1 values;
3. reproduce Category-42 saturation states `357,434,511,588,665,741,818`;
4. recover the seven 1024-entry Standard/Natural/Vivid contrast-family Q12 tone maps;
5. recover the gamma/remapping storage and consumer-domain evidence;
6. emit source paths, byte offsets, lengths and output hashes.

## Gamma-domain photographic diagnostic — INCONCLUSIVE

Workflow run:

```text
34188480412
```

Artifact:

```text
m11-r2-gamma-domain-hue-luma
sha256:b0392394a7ea24dc942b7a4623bf5d02e914fb4f35ffe7635fede1e3dbba5a19
```

The experiment attempted to use brightness-dependent Cb/Cr hue residuals as a discriminator between Y-only gamma and component/RGB nonlinear processing.

For H1, the aggregate median of per-pair median absolute hue-residual slopes was:

```text
ICC-managed linear sRGB: 1.8497 deg/stop
sRGB code values:         1.4681 deg/stop
code/linear ratio:        0.7937
```

The test's intended positive control predicted that component-wise sRGB OETF code space should show *more* brightness-dependent hue behavior than the ICC-managed linear domain. The opposite occurred.

Therefore this diagnostic does **not** isolate gamma placement and must not be used as evidence that gamma is Y-only, RGB/component-wise, or elsewhere.

Status:

```text
Y-only gamma placement: OPEN
RGB/component gamma placement: OPEN
```

The result is useful only as a falsification of this particular photographic diagnostic.

## ICC status of genuine JPEG corpus

All 12 genuine Leica M11 JPEGs inspected in the matched corpus embed the standard:

```text
sRGB IEC61966-2.1
```

ICC-managed conversion to canonical sRGB reproduces the earlier sRGB-decoded colour results closely. Therefore the H1 pre-CC0 reference-basis evidence remains valid; the nonlinear mismatch cannot be explained by an unhandled non-sRGB embedded JPEG profile.

## Current evidence boundary

```text
STRONG INFERENCE:
Xiaomi/scene XYZ D50
→ M11 Standard-A-like reference WB camera basis
→ CC0

RECORDED FIRMWARE EVIDENCE:
CC0
tone family structure/ranges
CC1
YCC matrix
Standard 115% Category-42 chroma state

OPEN:
exact tone samples
exact gamma samples
gamma placement/domain
clamps/rounding
additional chroma-dependent or luminance-dependent stages
final stage order edges
```

The next decisive work should be firmware-table reconstruction from the extracted archive, not another unconstrained photographic fit.
