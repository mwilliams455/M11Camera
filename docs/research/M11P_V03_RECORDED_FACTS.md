# M11-P v0.3 Recorded Forensic Facts

**Recovery date:** 2026-09-07  
**Original research date:** 2026-08-21  
**Firmware:** Leica M11-P 2.6.1

This file records technical facts recovered from the earlier project conversation after the original `M11P_color_forensics_v0.3` archive could not be located in the searchable File Library.

These values are stronger than guesses because they were written down during the original firmware analysis, but they remain **recorded prior findings**, not newly reproduced extraction output. They must be revalidated against the firmware before being promoted to canonical extractor assets.

## 1. Decompressed firmware filesystem landmarks

Earlier analysis recorded two ROMFS locations inside `LEICA_M11-P_2.6.1_unpacked.bin`:

```text
ROMFS #1 offset: 0x00E3A160
ROMFS #1 size:   3,629,024 bytes

ROMFS #2 offset: 0x0333DF70
ROMFS #2 size:   43,912,464 bytes
```

These are high-value anchors for rebuilding the extraction pass.

## 2. Candidate CC0 — Category 3

Recorded candidate Q9 matrix coefficients:

```text
 495   -58    63
  10   601  -111
  49  -255   705
```

Working normalization used by the recovered renderer:

```text
CC0 = matrix / 512
```

Recorded fallback/default matrix: identity with diagonal `512`.

Status:

- category identity: recorded prior finding;
- coefficient set: recorded prior finding;
- Q9 `/512` interpretation: used by recovered renderer;
- exact record address and consumer trace: must be reproduced.

## 3. Candidate CC1 — Category 13

Recorded low-ISO candidate Q9 coefficients:

```text
1041  -372  -157
-117   630    -1
  -4   -78   595
```

Working normalization:

```text
CC1 = matrix / 512
```

Recorded fallback/default matrix: identity with diagonal `512`.

Status:

- category identity: recorded prior finding;
- low-ISO coefficient set: recorded prior finding;
- exact ISO selection logic, record address and consumer trace: open.

## 4. Tone-control family

Recorded representation:

- 1024-entry gain table;
- Q12 unity = `4096`;
- input coordinate modeled as 0..1023;
- working arithmetic:

```text
Yout ~= (Yin * Gain[Yin]) >> 12
```

or equivalently in normalized reference code:

```text
Yout = Yin * Gain[Yin] / 4096
```

Recorded gain ranges by contrast state:

| Contrast | Recorded gain range |
| ---: | ---: |
| -3 | 4096 constant |
| -2 | 3004 .. 4348 |
| -1 | 2185 .. 4602 |
| 0 | 1911 .. 4867 |
| +1 | 1365 .. 5290 |
| +2 | 1057 .. 5742 |
| +3 | 793 .. 6225 |

The complete 1024 samples per state are not recovered here. Range information is useful for falsification but is insufficient to reconstruct the original curves exactly.

## 5. Gamma representation

Recorded representation:

```text
12-bit input coordinate
  -> approximately 4096 reconstructed positions
  -> 10-bit output range 0..1023
```

Recorded storage model:

- 256 coarse `uint16` nodes spanning the 10-bit output range;
- 256 groups × 16 four-bit differential substeps;
- differential payload total: 2048 bytes;
- each 8-byte group contains 16 nibbles/increments.

Two nibble orders were tested during the original analysis.

Recorded comparison:

| Decode | 2nd-difference roughness | RMS | Observation |
| --- | ---: | ---: | --- |
| high nibble first | 1179 | 0.5957 | smoother candidate |
| low nibble first | 1302 | 0.6153 | zero-size first-step artifacts |

Therefore **high-nibble-first** was selected as the stronger reconstruction candidate and is what the recovered renderer expects through `gamma_4096_high_nibble_first.csv`.

The exact raw gamma address/category framing is not sufficiently recovered in current history to encode into an extractor yet. Earlier discussion associated the gamma investigation with `r2y.bin`, but that association must be re-proven before it becomes canonical.

## 6. Saturation-dependent R2Y family — Category 42

Earlier analysis established Category 42 as the saturation-dependent family in `r2y.bin`.

Recorded dependency masks:

```text
0x200 -> saturation
0x400 -> contrast
0x800 -> sharpness
```

This corrected an earlier misclassification of 512/600-byte families as saturation-dependent; those families were sharpness-related.

Recorded Category 42 structure size:

```text
44 bytes
```

Recorded duplicated 10-bit chroma-like fields at packed offsets:

```text
+6
+8
```

Recorded effective saturation states:

| State | 10-bit field | Approx. scale |
| ---: | ---: | ---: |
| -3 | 357 | 70% |
| -2 | 434 | 85% |
| -1 | 511 | 100% |
| 0 | 588 | 115% |
| +1 | 665 | 130% |
| +2 | 741 | 145% |
| +3 | 818 | 160% |

Recorded relationship:

```text
round(512 * percent / 100) - 1
```

A monochrome/sentinel state `10` was recorded as mapping these chroma fields to zero.

This is particularly useful because it independently explains the recovered renderer's creative defaults:

```text
Natural  -> state -1 -> ~100%
Standard -> state  0 -> ~115%
Vivid    -> state +1 -> ~130%
```

## 7. Historical package names

The original work recorded creation of:

```text
M11P_color_forensics_v0.2.tar.gz
M11P_color_forensics_v0.3.tar.gz
```

The searchable File Library currently does not surface either archive by exact name.

## 8. What may be encoded now vs what must wait

### Safe recorded constants

The repo may retain, as *recorded prior findings*:

- CC0 candidate matrix values;
- CC1 low-ISO candidate matrix values;
- Q9 `/512` model;
- tone table length/Q12 unity/ranges;
- gamma storage dimensions and high-nibble-first preference;
- Category 42 saturation field values and state mapping;
- ROMFS landmark offsets/sizes.

### Must not be fabricated

Do not invent:

- full 1024-point tone curves;
- full 4096-point gamma curve;
- raw category record addresses not recovered above;
- exact CC0/CC1 consumer/order proof;
- gamma consumer/order proof;
- ISO selection rules for CC1;
- final transfer or clipping semantics.

## 9. Next extractor objective

Once the official/local firmware is available to the tooling, the canonical extractor should:

1. decompress the firmware;
2. verify the two ROMFS landmarks;
3. locate/extract the relevant R2Y and colour-control assets;
4. reproduce the recorded CC0/CC1 matrices;
5. reproduce Category 42 saturation values;
6. reproduce all tone samples and validate the recorded per-state ranges;
7. reproduce both gamma nibble-order candidates and confirm the recorded metrics;
8. emit a manifest containing source hashes, offsets, dimensions and output hashes.

Only after that should these recorded values be promoted from historical evidence to reproducible firmware assets.
