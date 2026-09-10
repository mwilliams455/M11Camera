# M11-P Category 42 / CsCo register semantics — REGISTERSEM1A

**Date:** 2026-09-10  
**Firmware:** Leica M11-P 2.6.1  
**Exact unpacked SHA-256:** `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`  
**Evidence branch:** `research/m11-cat42-consumer1a`

## Status

Category 42 is now PRIMARY Leica consumer evidence for the `CsCo` / `img_macro_drv_r2y_select_chroma_suppress_paraset` path. This note records the exact Standard map interpretation against the matching public Socionext/Milbeaut R2Y API structure.

It does **not** claim the pixel arithmetic is solved. Register semantics and transfer arithmetic are kept separate deliberately.

## Exact Leica Standard map

Category 42, saturation state `0`, exact signed 16-bit words:

```text
[1, 8, 0, 258, 588, 588, 505, 26, 0, -4, -20, 100, 771, 922, 0, 0, 0, 0, 0, 0, 0, 0]
```

Exact map SHA-256:

```text
b32ceea8c1b5249e11b2f6f118399d1d0bc190651e4b17da5a77f3810c81fb21
```

Mapped field-for-field to the 44-byte Milbeaut `R2yCtrlCs` structure:

```text
+0   csyEnable         = 1
+2   csy_mix_ratio     = 8
+4   csy_select_table  = 0
+6   csy_offset[0]     = 258
+8   csy_offset[1]     = 588
+10  csy_offset[2]     = 588
+12  csy_offset[3]     = 505
+14  csy_gain[0]       = 26
+16  csy_gain[1]       = 0
+18  csy_gain[2]       = -4
+20  csy_gain[3]       = -20
+22  csy_border[0]     = 100
+24  csy_border[1]     = 771
+26  csy_border[2]     = 922
+28  y_rev_enable      = 0
+30  c_rev_enable      = 0
+32  c_fixed_enable    = 0
+34  cb_fixed          = 0
+36  cr_fixed          = 0
+38  y_offset          = 0
+40  cb_offset         = 0
+42  cr_offset         = 0
```

## Public Milbeaut API semantics

The matching Socionext/Milbeaut API describes this block as Chroma Suppress and documents:

- `csyEnable`: when enabled, performs color-difference reduction by luminance/chroma reference;
- `csy_mix_ratio` / `CSYKY`: luminance/chroma mixing ratio, 4-bit range `0..8`;
- `csy_select_table` / `CSYTBL`: Chroma Suppress table selection;
- `csy_offset[4]` / `CSYOF`: four 10-bit offsets;
- `csy_gain[4]` / `CSYGA`: four signed 11-bit gains;
- `csy_border[3]` / `CSYBD`: three 10-bit area boundaries;
- optional Y/chroma reverse and fixed-chroma controls;
- output Y/Cb/Cr offsets after color-difference reduction.

The public driver copies these fields directly to the CSP register group (`CSYCTL`, `CSYOF`, `CSYGA`, `CSYBD`, `YCRVFX`, `CYFIX`, `YCOF`).

Public source references:

```text
https://github.com/ZMlogicL/companyTask/blob/f5fc84bd5c475f4c15017b7bff749f81c3618287/MILB_API/Project/ImageMacro/src/imr2y.h
https://github.com/ZMlogicL/companyTask/blob/f5fc84bd5c475f4c15017b7bff749f81c3618287/MILB_API/Project/ImageMacro/src/imr2yctrl3.c
https://github.com/ZMlogicL/companyTask/blob/f5fc84bd5c475f4c15017b7bff749f81c3618287/MILB_API/MILB_Header/include/Image/fr2y6a.h
```

## Saturation-state family

The creative saturation setting changes a piecewise-control family, not a scalar multiplier:

```text
state   offsets[0..3]       gains[0..3]      borders[0..2]
-3      258 357 357 332     26 0 -4 -19      31 946 992
-2      258 434 434 389     26 0 -4 -19      54 888 969
-1      258 511 511 447     26 0 -4 -20      77 831 946
 0      258 588 588 505     26 0 -4 -20     100 771 922
+1      258 665 665 563     26 0 -4 -20     124 713 899
+2      258 741 741 620     26 0 -4 -20     147 656 876
+3      258 818 818 677     26 0 -4 -20     170 598 853
```

The monochrome sentinel state `10` is also a 44-byte CsCo map but has a distinct parameter set.

## Important correction to the historical renderer

The old approximation interpreted the Standard value `588` as approximately `588 / 512 = 1.15` and therefore implemented:

```text
Cb *= 1.15
Cr *= 1.15
```

That interpretation is now disproven. In the actual 44-byte control structure, `588` is `csy_offset[1]` and `csy_offset[2]`; it is not a global saturation scale.

Therefore the historical 1.15 chroma multiplier must be treated as a temporary renderer approximation only. It must not be promoted as Leica firmware behavior.

## Pixel-arithmetic boundary

The following remain unresolved and must not be guessed:

- how Y and chroma magnitude/reference are mixed when `CSYKY=8`;
- exact selection and normalization of the input to the 4-region offset/gain/border transfer;
- exact piecewise equation and gain fixed-point scaling;
- signed rounding/saturation at each segment;
- whether Cb and Cr use magnitude, independent signed values, or a combined chroma norm;
- exact stage ordering versus all intermediate C-reference/edge/NR blocks;
- internal bit depth and clamp points before/after CSP.

## Device-validation consequence

`RENDER1B STAGEISO1A` intentionally does **not** implement a guessed Category-42 equation. It measures the current baseline's out-of-range behavior and two counterfactuals (gamma bypass and historical chroma-scale bypass) while preserving the saved Standard baseline image.

The next firmware/corpus step is to use those diagnostics plus genuine matched M11 DNG/JPEG pairs to constrain the missing CsCo arithmetic without visual tuning.
