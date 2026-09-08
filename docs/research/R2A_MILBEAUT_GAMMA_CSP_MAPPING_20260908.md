# R2A Milbeaut gamma / CSP hardware mapping

**Date:** 2026-09-08  
**Target firmware:** Leica M11-P 2.6.1  
**Status:** external hardware/API evidence + M11 primary-table correlation

## Scope and evidence boundary

The Leica firmware itself remains the primary source for the M11 R2Y resource tables. This note adds a second evidence source: a public Socionext/Milbeaut R2Y driver/API tree whose exported function names, register names, and gamma APIs match strings recovered from the Leica firmware (`Im_R2Y_Set_Gamma_Table`, gamma-table access controls, CC0/CC1/YC controls).

The public source is not Leica firmware and does not prove Leica's runtime parameter selections by itself. It is used to identify the meaning and shape of the hardware interfaces that the Leica firmware is clearly targeting.

## 1. Gamma table index semantics

The matching Milbeaut `im_r2y_set_gamma_table()` implementation explicitly defines:

```text
index 0  RGB common
index 1  R
index 2  G
index 3  B
index 4  Yb
```

The function rejects `tbl_index > 4`, matching the assertion string recovered from the Leica firmware.

This closes the generic hardware/API meaning of the five table indices. What Leica programs into each slot remains a Leica-consumer-trace question.

## 2. Native gamma storage shape

Each hardware gamma slot receives:

```text
256 x uint16 full/coarse entries
256 x uint64 differential entries
```

The full-table SRAM field is 10 bits wide.

The API exposes two gamma modes:

```text
12-bit input difference-type gamma mode
10-bit input gamma mode
```

This is an exact structural match for the primary M11 table pair:

```text
Category 20  512 bytes  = 256 x uint16 coarse/full nodes
Category 15  2048 bytes = 256 x uint64 differential words
```

The M11 high-nibble-first reconstruction yields 4096 input coordinates and 10-bit output values. Therefore the strongest current interpretation is that Category 15 + Category 20 together form one native Milbeaut 12-bit difference-gamma payload.

This does **not** yet prove which of RGB-common/R/G/B/Yb Leica loads with that payload.

## 3. Gamma is not naturally a post-YC Y-only block

The Milbeaut register block layout is:

```text
CCA0 / CC0     0x8080 - 0x8FFF
MCC            0x9000 - 0x9FFF
BTC            0xA000 - 0xA03F
Tone           0xA040 - 0xA05F
Gamma          0xA060 - 0xA07F
CCA1 / CC1     0xA080 - 0xA0FF
YC conversion  0xA100 - 0xA13F
YNR            0xA140 - ...
```

The common gamma table is explicitly named RGB-common, with separate R/G/B memories and a separate Yb memory. This makes the historical renderer assumption

```text
CC1 -> YC -> gamma(Y only)
```

structurally poor.

The register grouping strongly supports the hardware architecture:

```text
... -> Tone -> Gamma -> CC1 -> YC -> ...
```

This is **strong hardware-architecture evidence**, not yet a Leica runtime instruction trace. Exact arithmetic, clamp points, and any optional bypass/routing remain open.

The R2Y common-control API additionally exposes an MCC placement selector with two choices:

```text
MCC after CC0
MCC after gamma
```

which independently proves that gamma is a named internal pixel-domain boundary downstream of CC0.

## 4. Category 42 maps exactly onto Milbeaut Chroma Suppress control

Primary M11 evidence established:

```text
Category 42 map size = 44 bytes
8 maps: monochrome sentinel + saturation states -3..+3
```

The Milbeaut `R2yCtrlCs` Chroma Suppress structure contains exactly 22 16-bit fields = 44 bytes.

Its field order gives this raw-byte mapping:

```text
+0   csyEnable
+2   csy_mix_ratio
+4   csy_select_table
+6   csy_offset[0]
+8   csy_offset[1]
+10  csy_offset[2]
+12  csy_offset[3]
+14  csy_gain[0]
+16  csy_gain[1]
+18  csy_gain[2]
+20  csy_gain[3]
+22  csy_border[0]
+24  csy_border[1]
+26  csy_border[2]
+28  y_rev_enable
+30  c_rev_enable
+32  c_fixed_enable
+34  cb_fixed
+36  cr_fixed
+38  y_offset
+40  cb_offset
+42  cr_offset
```

This aligns directly with the M11 state-varying fields already reproduced:

```text
raw +8/+10 -> csy_offset[1]/[2] : 357,434,511,588,665,741,818
raw +12     -> csy_offset[3]     : 332,389,447,505,563,620,677
raw +20     -> csy_gain[3]       : -19,-19,-20,-20,-20,-20,-20
raw +22     -> csy_border[0]     : 31,54,77,100,124,147,170
raw +24     -> csy_border[1]     : 946,888,831,771,713,656,598
raw +26     -> csy_border[2]     : 992,969,946,922,899,876,853
```

The Milbeaut field widths also fit the M11 values:

```text
csy_offset[]  10-bit
csy_gain[]    11-bit signed
csy_border[]  10-bit
```

### Interpretation

Category 42 is therefore very strongly identified as the **Chroma Suppress control family**, not a single symmetric saturation multiplier.

The creative saturation states move luminance/chroma suppression offsets and borders and alter at least one signed gain. The earlier approximation

```text
Cb *= saturation_scale
Cr *= saturation_scale
```

is not an exact model of the hardware state.

Until the Leica selector call is instruction-traced, this identification is classified as **STRONG INFERENCE with exact structural/value correspondence**, not PRIMARY consumer proof.

## 5. Category 42 is a late Y/Cb/Cr-domain stage

The Milbeaut register map places Chroma Suppress (`CSP`) at:

```text
0xA580 - 0xBFFF
```

well downstream of YC conversion (`0xA100 - 0xA13F`) and after multiple YNR/edge/C-reference blocks.

The control documentation itself describes processing of Y, Cb and Cr and color-difference reduction.

Therefore the working M11 architecture should no longer place Category 42 immediately after gamma as a simple creative chroma scale. Its more plausible hardware location is a late Y/Cb/Cr-domain control stage.

Whether every intervening Milbeaut block is enabled in Leica Standard remains open and must be determined from Leica firmware consumers/parameter maps.

## 6. Category 14 offset clue

The four reproduced Category-13 CC1 maps occupy:

```text
0x002CD78C .. 0x002CD80B
```

Category-15 gamma-diff begins at:

```text
0x002CD838
```

The intervening region is exactly:

```text
0x2C = 44 bytes
```

This is a high-value clue that an intervening 44-byte map may occupy that space, plausibly Category 14, but this is **not yet proven** without the descriptor inventory. No semantic label is assigned here.

## 7. Current evidence state

### KNOWN — generic Milbeaut hardware/API

- gamma table indices 0..4 mean RGB-common/R/G/B/Yb;
- each table is 256 x uint16 full + 256 x uint64 differential;
- full gamma SRAM values are 10-bit;
- 12-bit input difference-gamma mode exists;
- Yb has dedicated gamma SRAM/access controls;
- hardware register blocks place Tone, Gamma, CC1 and YC consecutively in that order;
- Chroma Suppress is a 22 x 16-bit control structure and operates in Y/Cb/Cr/color-difference terms.

### PRIMARY M11 table evidence

- Category 15 = 2048-byte differential payload;
- Category 20 = 512-byte/256-node coarse payload;
- reconstructed gamma has 4096 coordinates and 10-bit output;
- Category 42 consists of eight 44-byte saturation-dependent maps with the reproduced state-varying values above.

### STRONG INFERENCE

- M11 Cat15 + Cat20 are a native 12-bit Milbeaut difference-gamma table pair;
- the preferred hardware architecture is Tone -> Gamma -> CC1 -> YC rather than post-YC Y-only gamma;
- Category 42 is the Milbeaut Chroma Suppress control family;
- Category 42 belongs late in the Y/Cb/Cr-domain path, not as an immediate post-gamma scalar.

### OPEN

- Leica's actual `GMMD` value in Standard;
- which gamma index/indices Leica loads;
- whether the same Cat15/20 table is copied to RGB-common and/or R/G/B/Yb;
- exact purpose and source signal of Yb in Leica's still path;
- exact gamma interpolation/evaluation arithmetic;
- exact clamp/rounding around Tone/Gamma/CC1/YC;
- direct Leica consumer proof for Category 42;
- Categories 14/16/17/25/41 descriptor shapes and consumers;
- which downstream YNR/edge/C-reference/CSP blocks are enabled for still JPEG rendering.

## 8. Next action

A compact extractor helper was added:

```text
tools/summarize_m11p_open_categories.py
```

Given the verified unpacked M11-P 2.6.1 image, it emits descriptor counts, map sizes, offsets, dependencies and hashes for Categories 14/16/17/25/41, plus decoded 16-bit values only for maps <=128 bytes. This allows the next successful firmware run to preserve the missing classification evidence without committing proprietary firmware/resource bytes.
