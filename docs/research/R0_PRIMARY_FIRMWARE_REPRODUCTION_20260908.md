# R0 Primary Firmware Reproduction — M11-P 2.6.1

**Date:** 2026-09-08  
**Source:** locally supplied original `LEICA_M11-P_2.6.1.FW`  
**Status:** primary byte-level table recovery completed

## Canonical source hashes

```text
firmware size          63,621,633 bytes
firmware SHA-256       0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83
body offset            0x48
packed size            63,621,561 bytes
packed-body MD5        c5d0e55f21fc91ea7626741e84377028
unpacked size          97,644,400 bytes
unpacked SHA-256       28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c
```

## Decompressor correction

The recovered public decompressor previously treated length and offset fields as at most two bytes. Genuine firmware proves they are big-endian base-128 continuation integers of arbitrary length.

Examples observed in the real stream:

```text
90 00       = 2048
A0 00       = 4096
C0 00       = 8192
81 80 00    = 16384
```

`tools/decompress_m11.py` and its regression tests were updated accordingly.

## R2Y resource

The image-processing parameter database is not in either Linux ROMFS tree. It is embedded in a separate resource region:

```text
R2YS start          0x002C9B38
resource size       53,008 bytes
R2YE marker         0x002D6A44
resource path       img/data/r2y.bin
envelope SHA-256    7a1a6440b14f086f33251a52de37d3c265132c62bf85eebad2a167ca57f01237
```

The database contains exactly **315 descriptors**. Descriptor map offsets are relative to the `R2YS` marker.

Canonical extractor:

```text
tools/extract_m11p_r2y_forensics.py
```

## Reproduced primary artifacts

### Category 3 — CC0

```text
 495   -58    63
  10   601  -111
  49  -255   705
```

Q denominator: 512.

### Category 13 — complete ISO-dependent CC1 family

```text
0..9999
1041 -372 -157
-117  630   -1
  -4  -78  595

10000..19999
 910 -290 -108
 -74  561   25
  22  -41  531

20000..39999
 806 -225  -69
 -39  506   45
  44  -12  480

40000..200000
 715 -169  -34
  -9  458   63
  61   15  436
```

Q denominator: 512.

### Category 24 — signed RGB/YCC-like basis

```text
 77  150   29
-43  -85  128
128 -107  -21
```

Denominator: 256.

### Category 42 — saturation family

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

### Category 5/6 — tone family

Seven Category-6 maps × 2048 bytes = seven × 1024 uint16 Q12 gain samples.

```text
contrast -3: 4096..4096
contrast -2: 3004..4348
contrast -1: 2185..4602
contrast  0: 1911..4867
contrast +1: 1365..5290
contrast +2: 1057..5742
contrast +3:  793..6225
```

Category-5 configuration reproduces luma weights `77,149,29`, sum 255, Q12 unity 4096.

### Category 15/20 — gamma representation

```text
Category 15 fine payload: 2048 bytes
Category 20 coarse table: 256 uint16 nodes / 512 bytes
```

High-nibble-first 4096-point reconstruction:

```text
second-difference L1   1179
second-difference RMS  0.5957429175741542
```

Low-nibble-first comparison:

```text
second-difference L1   1302
second-difference RMS  0.6153071049604038
```

The high-first table is therefore the canonical reconstruction.

## Upstream SRO colour management

A 132-byte signed-int32 structure beginning at `0x002C9A98` reproduces the exact M11 DNG dual-illuminant ColorMatrix pair plus the previously recorded third internal matrix.

```text
CM1 Q12, metadata 12 / 2850K
 2358  -546   -66
-2488  6300  1785
 -403   797  3504

CM2 Q12, metadata 12 / 6807K
 1700  -326  -200
-2354  5409   974
 -612   976  2276

additional raw matrix
 212  -165   -71
 -73   676    85
 -27   174   285
```

CM1/CM2 match genuine M11 DNG `ColorMatrix1/2` exactly at the Q12 integer level.

## Evidence boundary after R0 recovery

Now PRIMARY:

- decompression format;
- source/unpacked hashes;
- R2Y resource location and descriptor framing;
- CC0;
- all CC1 ISO matrices;
- Category-24 YCC basis;
- Category-42 saturation maps;
- exact seven tone tables;
- exact gamma coarse/fine representation and 4096-point reconstruction;
- upstream SRO CM1/CM2/internal matrix bytes.

Still OPEN:

- exact runtime consumer order;
- gamma placement/consumer;
- tone/CC0/CC1 arithmetic order at code level;
- fixed-point clamps and rounding;
- final output gamut/OETF sequence;
- semantics of the additional SRO matrix;
- still-path relevance and placement of Categories 16/17 and large 512/600-byte families.

Do not infer any of these open consumer semantics from the fact that a table exists.
