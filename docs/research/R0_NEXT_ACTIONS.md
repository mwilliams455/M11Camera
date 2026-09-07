# M11 R0 — Next Actions

**Updated:** 2026-09-07  
**Branch:** `research/m11-r0-evidence-input-space`

## Current position

The project has recovered enough prior work to avoid restarting from a LUT-emulation baseline.

Committed now:

- firmware decompressor;
- structured ROMFS probe;
- recovered firmware-derived reference renderer;
- recorded M11-P v0.3 constants/evidence notes;
- R2Y reconstruction notes;
- Xiaomi 15 Ultra dual-illuminant source-adapter work;
- synthetic regression tests and CI;
- R2Y forensic anchor scanner.

The missing primary evidence remains the original four-file `M11P_color_forensics_v0.3` table set or a fresh deterministic extraction of those tables from Leica M11-P firmware 2.6.1.

## Immediate reproduction sequence

### 1. Obtain firmware locally

Use Leica's official M11-P 2.6.1 firmware payload. Keep it outside the public repository.

Expected local filename:

```text
LEICA_M11-P_2.6.1.FW
```

### 2. Decompress

```bash
python tools/decompress_m11.py \
  /path/to/LEICA_M11-P_2.6.1.FW \
  --output /tmp/LEICA_M11-P_2.6.1_unpacked.bin
```

Record:

- source SHA-256;
- body offset;
- packed size;
- unpacked size;
- packed-body MD5 verification;
- unpacked SHA-256.

### 3. Recover ROMFS files

```bash
python tools/m11_romfs_probe.py \
  /tmp/LEICA_M11-P_2.6.1_unpacked.bin \
  --scan \
  --list-files \
  --find-file r2y.bin \
  --extract-found-dir /tmp/m11p_extracted \
  --carve-dir /tmp/m11p_romfs
```

Historical ROMFS landmarks to test, not hard-code:

```text
0x00E3A160  size 3,629,024
0x0333DF70  size 43,912,464
```

### 4. Scan `r2y.bin` for independent anchors

```bash
python tools/r2y_anchor_scan.py \
  /tmp/m11p_extracted/r2y.bin \
  --json /tmp/r2y_anchor_report.json
```

Strong recorded anchors:

- CC0 Q9 matrix: `495 -58 63 / 10 601 -111 / 49 -255 705`;
- low-ISO CC1 Q9 matrix: `1041 -372 -157 / -117 630 -1 / -4 -78 595`;
- Category 24 Y/Cb/Cr-like matrix: `77 150 29 / -43 -85 128 / 128 -107 -21`;
- Category 42 saturation values: `357 434 511 588 665 741 818`.

A byte-pattern hit is only a lead. It does not prove descriptor framing or semantic use.

### 5. Reconstruct the 315-map R2Y descriptor database

The parser must be derived from consistency constraints rather than guessed from the old category numbers.

A candidate descriptor layout is acceptable only if it simultaneously produces:

- 315 descriptors;
- bounded map offsets/sizes;
- internally consistent dependency records;
- recovery of the known Category 3/13/24/42 payload signatures;
- coherent grouping by recorded dependency bits `0x200`, `0x400`, `0x800`.

### 6. Reproduce complete primary table outputs

The canonical extractor should emit equivalents of:

```text
category3_CC0_candidate.json
category13_CC1_candidate.json
tone_q12_reconstructed_curves.csv
gamma_4096_high_nibble_first.csv
```

Each output must carry source offsets and SHA-256 values in a manifest.

### 7. Only then promote renderer constants

After fresh extraction reproduces the recorded matrices, tone ranges, gamma reconstruction behavior and saturation states, the renderer can switch from `recorded prior finding` to `reproduced firmware evidence` for those pieces.

## R1 boundary after extraction

Do not tune photographs immediately after table recovery.

The next questions are architectural:

1. exact signal domain entering CC0;
2. CC0 -> tone -> CC1 ordering proof;
3. whether gamma is actually applied in the recovered Y-like domain and at what point;
4. final output transfer/OETF;
5. clipping/headroom and integer rounding semantics;
6. ISO-dependent CC1 selection;
7. still-path local/spatial stages that materially affect the M11 look.

These should be solved using genuine M11/M11-P DNG + in-camera JPEG pairs and firmware consumer traces.

## Xiaomi port boundary

The Xiaomi 15 Ultra should not be mapped directly into historical M11 LUTs.

Target architecture remains:

```text
Xiaomi physical-camera RAW
-> native source characterization
-> scene-referred interchange space
-> explicit M11 input-space bridge
-> validated M11 renderer
-> output/JPEG
```

Main camera + Standard remains the first port target. Natural/Vivid and the other rear modules come later.
