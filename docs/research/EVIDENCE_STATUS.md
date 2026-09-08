# M11 Evidence Status

**Updated:** 2026-09-08

## Primary firmware reproduction completed

A locally supplied original `LEICA_M11-P_2.6.1.FW` has now been decompressed and inspected directly.

Verified updater / unpacking facts:

```text
firmware size          63,621,633 bytes
firmware SHA-256       0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83
body offset            0x48
packed size            63,621,561 bytes
packed-body MD5        c5d0e55f21fc91ea7626741e84377028
unpacked size          97,644,400 bytes
unpacked SHA-256       28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c
```

The decompressor was corrected during this reproduction: length/offset fields are arbitrary-length base-128 continuation integers, not merely one- or two-byte fields. Genuine firmware contains three-byte values such as `81 80 00 = 16384`.

Both historical ROMFS landmarks reproduce:

```text
0x00E3A160  recorded size 3,629,024 bytes
0x0333DF70  recorded size 43,912,464 bytes
```

The image-processing R2Y data is not contained in those Linux ROMFS filesystems. It is embedded in a separate resource region between them.

## R2Y database — now primary evidence

The embedded default R2Y resource is bounded by:

```text
R2YS start          0x002C9B38
resource size       53,008 bytes
R2YE marker         0x002D6A44
resource path       img/data/r2y.bin
envelope SHA-256    7a1a6440b14f086f33251a52de37d3c265132c62bf85eebad2a167ca57f01237
```

The database contains exactly **315 variable-size descriptors**. Descriptor `map_offset` values are relative to the `R2YS` marker. This removes the earlier map-offset ambiguity.

Canonical extractor:

```text
tools/extract_m11p_r2y_forensics.py
```

### Category 3 — CC0

Primary Q9 matrix:

```text
 495   -58    63
  10   601  -111
  49  -255   705
```

Normalize by `/512`.

Literal matrix signature occurs at absolute firmware offset:

```text
0x002CE27E
```

### Category 13 — CC1 ISO family

All four complete Q9 matrices are now reproduced:

```text
ISO 0..9999
1041  -372  -157
-117   630    -1
  -4   -78   595

ISO 10000..19999
 910  -290  -108
 -74   561    25
  22   -41   531

ISO 20000..39999
 806  -225   -69
 -39   506    45
  44   -12   480

ISO 40000..200000
 715  -169   -34
  -9   458    63
  61    15   436
```

Normalize by `/512`.

The low-ISO literal signature begins at:

```text
0x002CD78E
```

### Category 24 — RGB to Y/Cb/Cr-like basis

Primary signed coefficients:

```text
 77  150   29
-43  -85  128
128 -107  -21
```

Normalize by `/256`.

Absolute map location:

```text
0x002CE238
```

### Category 42 — saturation family

Category-42 descriptors carry flags `0x206`, including the recorded saturation dependency bit `0x200` plus common selector bits.

Duplicated 10-bit fields reproduce exactly:

```text
state 10 ->   0   monochrome sentinel
state -3 -> 357   ~70%
state -2 -> 434   ~85%
state -1 -> 511   ~100%
state  0 -> 588   ~115%
state +1 -> 665   ~130%
state +2 -> 741   ~145%
state +3 -> 818   ~160%
```

## Tone family — now primary evidence

Category 5 contains the tone configuration maps and Category 6 contains seven contrast-dependent tone maps.

Common tone configuration reproduces:

```text
luma weights      77,149,29
weight sum        255
Q12 unity         4096
```

Category-6 maps are exactly seven × 2048-byte arrays = seven × 1024 little-endian uint16 Q12 gains.

Primary ranges:

```text
contrast -3: 4096..4096
contrast -2: 3004..4348
contrast -1: 2185..4602
contrast  0: 1911..4867
contrast +1: 1365..5290
contrast +2: 1057..5742
contrast +3:  793..6225
```

The first curve map begins at:

```text
0x002D323C
```

The exact 1024 samples/state are emitted as:

```text
tone_q12_reconstructed_curves.csv
```

## Gamma representation — now primary evidence

The historical representation is reproduced exactly from descriptor-framed maps:

```text
Category 15: 2048-byte fine differential payload
Category 20: 512-byte / 256-node uint16 coarse table
```

Primary map locations:

```text
Category 15 fine    0x002CD7F8
Category 20 coarse  0x002CDF98
```

High-nibble-first reconstruction:

```text
4096 output positions
10-bit output 0..1023
2nd-difference L1   1179
2nd-difference RMS  0.5957429175741542
```

Low-nibble-first comparison:

```text
2nd-difference L1   1302
2nd-difference RMS  0.6153071049604038
```

Therefore high-nibble-first remains the selected table reconstruction, now from primary firmware bytes rather than recovered historical files.

Important boundary: **the table representation is primary evidence; runtime gamma placement is still OPEN.**

## Upstream SRO colour-management structure — now primary evidence

The firmware contains `img/data/sro.bin` immediately before the embedded R2Y resource. A 132-byte signed-int32 colour-management structure starts at:

```text
0x002C9A98
```

Its first two Q12 matrices exactly equal genuine M11 DNG `ColorMatrix1/2`:

```text
CM1 / 4096, metadata 12,2850K
 2358  -546   -66
-2488  6300  1785
 -403   797  3504

CM2 / 4096, metadata 12,6807K
 1700  -326  -200
-2354  5409   974
 -612   976  2276
```

The previously recorded additional raw matrix is also reproduced:

```text
 212  -165   -71
 -73   676    85
 -27   174   285
```

Its exact consumer/scaling semantics remain OPEN.

## Genuine Leica matched corpus status

Twelve genuine Leica M11 DNG/JPEG pairs from Photography Blog are now validated and used as a regression corpus.

The strongest current input-space result is documented in:

```text
docs/research/M11_STANDARD_A_REFERENCE_BASIS_HYPOTHESIS.md
```

Direct as-shot white-balanced M11 camera RGB -> fixed CC0/CC1 gives approximately 8.16% mean scaled matrix residual. Mapping the scene through the DNG colour-management path into the fixed Standard-A white-balanced M11 reference-camera basis before the same CC pair reduces this to approximately 0.864% mean / 0.877% max across all 12 samples.

Pixel-level matched DNG/JPEG chroma-angle validation also favors that H1 bridge over direct H0 on 10/12 pairs.

The bridge therefore remains **STRONG INFERENCE**, not yet firmware-consumer proof.

## Current working architecture

```text
Xiaomi RAW
→ Xiaomi physical-camera source calibration
→ linear scene-referred XYZ D50
→ M11 Standard-A reference WB camera basis          [STRONG INFERENCE]
→ Category 3 CC0                                    [PRIMARY TABLE]
→ Category 5/6 tone                                 [PRIMARY TABLE]
→ Category 13 CC1                                   [PRIMARY TABLE]
→ Category 24 Y/Cb/Cr-like stage                    [PRIMARY TABLE]
→ gamma/nonlinear consumer                          [TABLE PRIMARY, PLACEMENT OPEN]
→ Category 42 mode chroma                            [PRIMARY TABLE]
→ output gamut / transfer                            [OPEN]
→ JPEG
```

## Invalidated / inconclusive photographic diagnostics

The hue-vs-luminance gamma-domain test is **not** treated as evidence for Y-only or RGB/component gamma. Its intended sRGB code-space positive control behaved opposite to prediction, indicating the statistic was dominated by scene/demosaic/JPEG effects rather than isolating gamma placement.

Do not use that experiment to promote a gamma-placement hypothesis.

## Remaining high-priority questions

R0 table recovery is effectively closed. The next work is consumer tracing and exact arithmetic:

- exact consumer/order of Category 5/6 tone versus CC0/CC1;
- exact consumer and placement of Category 15/20 gamma representation;
- final RGB/YCC conversion ordering;
- integer bit depth, clamp points and rounding;
- output transfer/OETF and gamut conversion;
- semantics of the additional SRO internal matrix;
- whether Categories 16/17 and the large 512/600-byte families affect the still-render path and at what stage;
- ISO-selection semantics beyond the now-explicit Category-13 ranges;
- Android parity only after the offline Standard path is closed.

## Evidence policy

Historical LUTs, Cobalt profiles and old `M11P_color_forensics_v0.3` outputs remain regression controls only. They are no longer needed as primary sources for CC0/CC1/tone/gamma constants because those values now reproduce directly from the original firmware.

No proprietary Leica firmware bytes are committed to the public repository.
