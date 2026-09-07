# R2Y Database Reconstruction Target

**Evidence class:** recorded prior finding, not yet reproduced  
**Original analysis:** 2026-08-21  
**Recovery note:** 2026-09-07

The earlier M11-P 2.6.1 firmware analysis successfully decoded `r2y.bin` as a parameter database containing **315 parameter-map descriptors**.

The recovered description of each descriptor says it carried, at minimum:

- dependency mask;
- descriptor size;
- map size;
- map offset;
- dependency values.

The exact binary field offsets, endianness, table header layout and original Python parser were not preserved in the currently recoverable project history. Those fields therefore remain a reconstruction target and must not be guessed into the canonical extractor.

## Known dependency bits

Later analysis established the following dependency-mask meanings:

```text
0x200  saturation
0x400  contrast
0x800  sharpness
```

This was important because larger 512/600-byte parameter families initially suspected to be saturation controls were later shown to be sharpness-dependent. Category 42 remained the confirmed saturation-dependent family.

## Known category anchors

| Category | Recorded role | Current evidence status |
| ---: | --- | --- |
| 3 | CC0 candidate | matrix recorded; raw record location/framing must be reproduced |
| 13 | low-ISO CC1 candidate | matrix recorded; ISO selection and raw record location must be reproduced |
| 24 | RGB → Y/Cb/Cr-like matrix | 9 signed coefficients recorded by reference renderer; raw record details must be reproduced |
| 42 | saturation-dependent R2Y family | 44-byte structure and state fields recorded; descriptor framing must be reproduced |

Recorded Category 24 coefficient matrix:

```text
  77   150    29
 -43   -85   128
 128  -107   -21
```

The recovered renderer normalizes these coefficients by `256`. This matrix was described during the original analysis as BT.601-like and was used to confirm byte order/signedness during R2Y decoding. Exact source offsets are not currently recovered.

## Reconstruction strategy once `r2y.bin` is extracted

1. Record the exact structured ROMFS path, header offset, data offset, size and SHA-256 of `r2y.bin`.
2. Preserve the untouched file locally and work only from a hash-identified copy.
3. Re-identify the descriptor table by testing candidate layouts against the recorded invariant of **315 maps**.
4. Reject any candidate parser that does not produce internally consistent descriptor sizes, map offsets and bounds.
5. Use the recorded Category 3, 13, 24 and 42 payload signatures as independent anchors rather than hard-coding their presumed locations.
6. Confirm dependency-mask semantics by grouping maps by `0x200`, `0x400` and `0x800` and reproducing the recorded family behavior.
7. Only after the descriptor layout is reproduced should exact raw offsets be promoted into the canonical manifest.

## Strong anchor signatures

These signatures can be searched within candidate map payloads after descriptor framing is recovered:

### Category 3 CC0 Q9 matrix

```text
495  -58   63
 10  601 -111
 49 -255  705
```

### Category 13 low-ISO CC1 Q9 matrix

```text
1041 -372 -157
-117  630   -1
  -4  -78  595
```

### Category 24 signed matrix

```text
77 150 29 -43 -85 128 128 -107 -21
```

### Category 42 saturation-state fields at payload offsets +6/+8

```text
357 434 511 588 665 741 818
```

These values are search anchors, not permission to infer a descriptor format from coincidence alone.
