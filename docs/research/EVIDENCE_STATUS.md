# M11 Evidence Status

**Updated:** 2026-09-08

## Primary firmware reproduction completed

A locally supplied original `LEICA_M11-P_2.6.1.FW` has now been decompressed and inspected directly with the canonical extractor:

```text
tools/extract_m11p_forensics.py
```

Verified updater / unpacking facts:

```text
firmware size          63,621,633 bytes
firmware SHA-256       0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83
body offset            0x48
packed size            63,621,561 bytes
packed-body MD5        c5d0e55f21fc91ea7626741e84377028
unpacked size          97,644,400 bytes
unpacked SHA-256       28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c
compression marker     0xA2
```

The decompressor was corrected during this reproduction: copy length/distance fields are arbitrary-length base-128 continuation integers, not merely one- or two-byte fields. Genuine firmware contains three-byte values such as `81 80 00 = 16384`.

Both historical ROMFS landmarks reproduce exactly:

```text
0x00E3A160  3,629,024 bytes
SHA-256 dc92443ded0cd6cac359ebd2f6598365bca8412313be301831b9c22773e86472

0x0333DF70  43,912,464 bytes
SHA-256 b2a3d8ba7d83427261f9911dce36b9de0010b1af7cc3f60b6c05c105f58580a9
```

The image-processing R2Y data is not contained in those Linux ROMFS filesystems. It is embedded in a separate resource region between them.

## R2Y database — primary evidence

The unique default R2Y resource is:

```text
R2YS start          0x002C9B38
resource size       53,008 bytes
R2YE marker         0x002D6A44
embedded path       img/data/r2y.bin
resource SHA-256    7a1a6440b14f086f33251a52de37d3c265132c62bf85eebad2a167ca57f01237
```

The database contains exactly **315 variable-size descriptors**. The descriptor table terminates exactly at the first map offset. Descriptor `map_offset` values are relative to the `R2YS` marker.

Observed dependency bits now reproduce the historical classification:

```text
0x200  saturation
0x400  contrast
0x800  sharpness
```

### Category 3 — CC0

Map:

```text
map absolute offset   0x002CE27C
matrix starts at      0x002CE27E
map size              42 bytes
map SHA-256           31e7bc2aed47b9b3c54321210f888dc8f982d1c59ae71009dac9c9d1d6fff402
```

Primary Q9 matrix:

```text
 495   -58    63
  10   601  -111
  49  -255   705
```

Normalize by `/512`.

### Category 13 — CC1 ISO family

Four complete 32-byte maps reproduce:

```text
ISO 0..9999       map 0x002CD78C
1041  -372  -157
-117   630    -1
  -4   -78   595

ISO 10000..19999  map 0x002CD7AC
 910  -290  -108
 -74   561    25
  22   -41   531

ISO 20000..39999  map 0x002CD7CC
 806  -225   -69
 -39   506    45
  44   -12   480

ISO 40000..200000 map 0x002CD7EC
 715  -169   -34
  -9   458    63
  61    15   436
```

Normalize by `/512`.

### Category 24 — RGB to Y/Cb/Cr-like basis

```text
map absolute offset   0x002CE238
map size              18 bytes
map SHA-256           8378a1f64039be01f3c8a9b761da6dc270d9a458e5fedd8e407f010d1901fd56
```

Primary signed coefficients:

```text
 77  150   29
-43  -85  128
128 -107  -21
```

Normalize by `/256`.

## Tone family — primary evidence

Category 5 provides the common tone configuration and Category 6 provides the contrast-dependent gain tables.

Category-5 common map:

```text
absolute offset       0x002D3200
luma weights          77,149,29
weight sum            255
Q12 unity             4096
```

Category-6 contains exactly seven × 2048-byte arrays = seven × 1024 little-endian uint16 Q12 gains:

```text
contrast -3  0x002D323C  4096..4096
contrast -2  0x002D3A3C  3004..4348
contrast -1  0x002D423C  2185..4602
contrast  0  0x002D4A3C  1911..4867
contrast +1  0x002D523C  1365..5290
contrast +2  0x002D5A3C  1057..5742
contrast +3  0x002D623C   793..6225
```

The exact 1024 samples/state are emitted as:

```text
tone_q12_reconstructed_curves.csv
```

The Standard map SHA-256 is:

```text
ce4ca12c0c894919102f10d65d5b2af72461146b18ad5b91ed55750f23c0f75a
```

## Gamma representation — primary table evidence

The historical gamma representation is reproduced exactly from descriptor-framed maps:

```text
Category 15 fine differential payload
  absolute offset     0x002CD838
  size                2048 bytes
  SHA-256             dfcedcc74c5acb282b25462bf048bba7f09e6dd75b4428707409f448f892d602

Category 20 coarse nodes
  absolute offset     0x002CE038
  size                512 bytes / 256 uint16 nodes
  output range        0..1023
  SHA-256             fad334bb736efc59df53cac4654b73668958e03e08c2ac3c2bf6c496ff14af56
```

Reconstruction is performed group-by-group: initialize the accumulator from one coarse node, decode 16 four-bit increments from the corresponding eight fine bytes, append the current accumulator before each increment, then add the nibble.

High-nibble-first reproduces the historical metrics exactly:

```text
4096 output positions
10-bit output 0..1023
2nd-difference L1   1179
2nd-difference RMS  0.5957429175741542
u16LE SHA-256       29051ff01ee591e954fd26d98e23c30553da180a7f9706aa137269cd0690c2a3
```

Low-nibble-first:

```text
2nd-difference L1   1302
2nd-difference RMS  0.6153071049604038
u16LE SHA-256       970b68e1c085bf3b3371c7070f4c82e708a3740b19499b67402255b3e2e4b21d
```

Therefore high-nibble-first is now **primary reproduced table evidence**. Runtime gamma consumer/table-index semantics and physical datapath placement remain OPEN.

## Category 42 — saturation-dependent multi-field family

Category-42 consists of eight 44-byte maps with descriptor flags `0x206`: monochrome sentinel state `10`, then states `-3..+3`.

Maps:

```text
state 10  0x002D30A0
state -3  0x002D30CC
state -2  0x002D30F8
state -1  0x002D3124
state  0  0x002D3150
state +1  0x002D317C
state +2  0x002D31A8
state +3  0x002D31D4
```

The historically recorded duplicated saturation-like fields are at **raw map byte offsets +8 and +10**. The older `+6/+8` notation was relative to a payload after the initial two-byte word.

They reproduce exactly:

```text
state 10 ->   0
state -3 -> 357
state -2 -> 434
state -1 -> 511
state  0 -> 588
state +1 -> 665
state +2 -> 741
state +3 -> 818
```

However, Category 42 is **not an exact single symmetric chroma multiplier**. Several additional fields vary systematically with the creative saturation state. For states `-3..+3`, selected int16 fields are:

```text
raw +8/+10 : 357,434,511,588,665,741,818
raw +12     : 332,389,447,505,563,620,677
raw +20     : -19,-19,-20,-20,-20,-20,-20
raw +22     : 31,54,77,100,124,147,170
raw +24     : 946,888,831,771,713,656,598
raw +26     : 992,969,946,922,899,876,853
```

This invalidates the old renderer assumption that Standard can be represented exactly by `Cb *= 1.15; Cr *= 1.15`. The 588 field remains useful as one component of the Standard state, but the complete 44-byte map must be understood/ported.

## Upstream SRO colour-management structure — primary evidence

The embedded default `img/data/sro.bin` block immediately precedes R2YS.

```text
path string offset    0x002C9A80
7 bytes 0x55 fill
132-byte core offset  0x002C9A98
4 bytes 0x55 trailing fill
```

The 132-byte core is 33 signed int32 words.

CM1 Q12, followed by metadata `[12,2850]`:

```text
 2358  -546   -66
-2488  6300  1785
 -403   797  3504
```

CM2 Q12, followed by metadata `[12,6807]`:

```text
 1700  -326  -200
-2354  5409   974
 -612   976  2276
```

Dividing CM1/CM2 by 4096 reproduces genuine M11 DNG `ColorMatrix1/2` exactly.

The additional raw 3×3 block, followed by metadata `[0,6807]`, is also reproduced:

```text
 212  -165   -71
 -73   676    85
 -27   174   285
```

Its exact scaling and consumer remain OPEN.

## Genuine Leica matched corpus status

Twelve genuine Leica M11 DNG/JPEG pairs from Photography Blog are used as a regression corpus.

The strongest current input-space result is documented in:

```text
docs/research/M11_STANDARD_A_REFERENCE_BASIS_HYPOTHESIS.md
```

Direct as-shot white-balanced M11 camera RGB -> fixed CC0/CC1 gives approximately 8.16% mean scaled matrix residual. Mapping each scene through the DNG colour-management path into the fixed Standard-A white-balanced M11 reference-camera basis before the same CC pair reduces this to approximately 0.864% mean / 0.877% max across all 12 samples.

Pixel-level matched DNG/JPEG chroma-angle validation also favors H1 over direct H0 on 10/12 pairs.

The bridge remains **STRONG INFERENCE** pending an exact upstream SRO consumer trace, although the physical recovery of the genuine DNG CM1/CM2 values immediately before R2YS materially strengthens it.

## Firmware consumer / selector evidence

Firmware debug/symbol strings expose parameter selectors for:

```text
img_macro_drv_r2y_select_colorcorrection0_paraset
img_macro_drv_r2y_select_btc_offset_paraset
img_macro_drv_r2y_select_tone_ctrl_paraset
img_macro_drv_r2y_select_colorcorrection1_paraset
img_macro_drv_r2y_select_yc_paraset
img_macro_drv_r2y_select_gamma_paraset
```

Low-level driver strings expose controls including:

```text
Im_R2Y_Ctrl_CC0_Matrix
Im_R2Y_Ctrl_Tone
Im_R2Y_Ctrl_Gamma
Im_R2Y_Ctrl_CC1_Matrix
Im_R2Y_Ctrl_Yc_Convert
Im_R2Y_Set_Gamma_Table
Im_R2Y_Set_GammaYbTblAccessEnable
```

`Im_R2Y_Set_Gamma_Table` checks `tbl_index > 4`, showing at least five hardware gamma table indices, and the macro selector contains an `RGBYB TABLE` diagnostic. This makes the historical reference-renderer assumption “apply the reconstructed gamma only to Y” explicitly unproven. Physical datapath order and table-index meaning require consumer/register tracing.

The textual selector/API order is evidence of parameter programming structure, **not by itself proof of physical pixel datapath order**.

## Current working architecture

```text
Xiaomi RAW
→ Xiaomi physical-camera source calibration
→ linear scene-referred XYZ D50
→ M11 Standard-A reference WB camera basis          [STRONG INFERENCE]
→ Category 3 CC0                                    [PRIMARY TABLE]
→ Category 5/6 tone                                 [PRIMARY TABLE; consumer arithmetic to trace]
→ Category 13 CC1                                   [PRIMARY TABLE]
→ Category 24 Y/Cb/Cr-like stage                    [PRIMARY TABLE]
→ gamma/nonlinear hardware                          [TABLE PRIMARY; consumer/placement OPEN]
→ Category 42 creative chroma/control stage         [PRIMARY MULTI-FIELD TABLE; semantics OPEN]
→ output gamut / transfer                           [OPEN]
→ JPEG
```

The order above remains a working architecture until the hardware consumer trace closes the relevant boundaries.

## Invalidated / inconclusive photographic diagnostics

The hue-vs-luminance gamma-domain experiment is **not** evidence for Y-only or RGB/component gamma. Its intended sRGB code-space positive control behaved opposite to prediction, so the statistic is treated as scene/demosaic/JPEG-confounded rather than a stage-order discriminator.

Similarly, any earlier matched-JPEG calculation that modeled Category 42 as only a symmetric `1.15` Standard chroma multiplier is superseded by the primary 44-byte Category-42 maps.

## Remaining high-priority questions

R0 table recovery is effectively complete. Current R2 priorities are:

- trace exact consumers/registers for CC0, before-tone/BTC, tone, CC1, YC and gamma;
- determine gamma table index meanings and the special Yb path;
- establish physical pixel datapath order independently of selector call order;
- decode all meaningful fields in Category 42 and identify the still-render consumer;
- determine integer bit depth, clamp points and rounding at each stage;
- determine final gamut/output transfer;
- resolve the additional SRO internal matrix semantics;
- inspect Categories 14/16/17/25/41 and sharpness-dependent 512/600-byte families only where consumer evidence shows they affect the still path;
- port to Android only after the offline Standard path is structurally closed.

## Evidence policy

Historical LUTs, Cobalt profiles and old `M11P_color_forensics_v0.3` outputs remain regression controls only. They are no longer primary sources for CC0, CC1, tone, gamma representation, Category 24, Category 42 or SRO colour-management constants because those values now reproduce directly from the original firmware.

No proprietary Leica firmware bytes are committed to the public repository.
