# R0 Recovery Audit

**Date:** 2026-09-07  
**Target:** Leica M11-P 2.6.1 firmware-derived renderer recovery  
**Branch:** `research/m11-r0-evidence-input-space`

## Purpose

Recover the earlier M11 work without promoting test LUTs or visual tuning into primary firmware evidence.

The project now uses three evidence classes:

1. **Recovered implementation evidence** — scripts and structures recovered from prior firmware work.
2. **Generated regression controls** — LUTs or rendered outputs created from a working model; useful for regression but not independent proof of that model.
3. **Unrecovered primary extraction assets** — table files or firmware-derived artifacts referenced by the recovered code but not currently available in the accessible project archive.

## Recovered implementation evidence

### Firmware decompressor

Recovered source: `decompress_m11.py`, originally created 2026-08-21.

Repo recovery:

- `tools/decompress_m11.py`

The recovered format model reads:

- payload offset: little-endian u32 at file offset `0x04`;
- unpacked size: little-endian u32 at `0x0c`;
- packed size: little-endian u32 at `0x14`;
- expected packed-payload MD5: bytes `0x18..0x27`;
- first packed payload byte as the escape/back-reference marker;
- literal marker encoded as `marker, 0`;
- length/offset fields using one-byte 7-bit values or two-byte extended values.

The repo version parameterizes input/output paths and adds bounds checks without changing the recovered decompression semantics.

### Reference renderer

Recovered source: `leica_m11_reference_renderer.py`, originally created 2026-08-21.

Repo recovery:

- `renderer/reference/leica_m11_reference_renderer.py`

Recovered working model:

```text
normalized scene-linear M11 working RGB
  -> candidate CC0 / 512
  -> 1024-point Q12 luminance-dependent tone family
  -> candidate CC1 / 512
  -> Leica RGB -> Y/Cb/Cr-like integer basis
  -> reconstructed 4096-point gamma on Y [PLACEMENT NOT PROVEN]
  -> mode-dependent symmetric chroma scale
  -> inverse Y/Cb/Cr-like basis
  -> clamp
```

Recovered mode state model:

| Mode | Contrast state | Chroma scale |
| --- | ---: | ---: |
| Natural | -1 | 1.00 |
| Standard | 0 | 1.15 |
| Vivid | +1 | 1.30 |

Recovered Y/Cb/Cr-like matrix coefficients, normalized by 256:

```text
[  77,  150,   29 ]
[ -43,  -85,  128 ]
[ 128, -107,  -21 ]
```

Recovered tone-luma weights, normalized by 255:

```text
[77, 149, 29]
```

## Unrecovered primary extraction assets

The renderer references a directory historically named `M11P_color_forensics_v0.3` containing at least:

```text
category3_CC0_candidate.json
category13_CC1_candidate.json
tone_q12_reconstructed_curves.csv
gamma_4096_high_nibble_first.csv
```

A File Library recovery pass across the original August 20–22 work window found the renderer, decompressor, and generated M11 LUT controls, but did not surface these four table files as standalone recoverable assets.

Therefore the project must **not** currently claim the numeric CC0, CC1, 1024-point tone family, or 4096-point gamma samples are independently reproduced from source firmware in this repository.

The next firmware-evidence milestone is to re-extract these assets from a locally supplied M11-P 2.6.1 firmware image or recover the original `M11P_color_forensics_v0.3` directory.

## Generated regression controls recovered in the archive

Examples include:

- `Leica_M11P_Natural_FULL_REFERENCE_LINEAR_33.cube`
- `Leica_M11P_Standard_FULL_REFERENCE_LINEAR_33.cube`
- `Leica_M11P_Vivid_FULL_REFERENCE_LINEAR_33.cube`
- `Leica_M11P_Standard_CC_PLUS_CHROMA_4080K_sRGB_33.cube`
- later colour-locked / warm-guard / lens-specific test cubes.

These are valuable because they preserve outputs of prior branches and can catch implementation drift after table recovery.

They are **not** independent evidence for:

- CC0/CC1 identity or semantic direction;
- gamma placement;
- Leica input working space;
- output transfer;
- clipping/rounding semantics;
- local/spatial processing;
- Xiaomi sensor-to-M11 bridging.

For that reason generated `.cube` files are ignored by default in the new repository.

## Genuine Leica validation material

No genuine matching M11/M11-P DNG + in-camera JPEG pair was found in the currently searchable project File Library during this recovery pass, and no M11 asset was returned by the connected Dropbox search.

This does not prove such files never existed; it only records the accessible recovery state on 2026-09-07.

## R0 evidence rule

A value or stage moves from **working hypothesis** to **firmware-proven / reproducible** only when at least one of the following exists in the repository:

1. a deterministic extractor from a locally supplied firmware image plus a stable output hash/manifest; or
2. a code-path trace that proves the value's consumer, scaling and role; or
3. independent validation against genuine M11 DNG/JPEG evidence where firmware extraction alone cannot resolve semantics.

Generated LUTs and visual similarity are not sufficient on their own.

## Immediate next work

1. Keep recovered decompression and renderer code compiling in CI.
2. Recover/rebuild the four-table forensic set.
3. Replace ad-hoc table recovery with a canonical extractor + manifest + hashes, following the successful discipline used in the M10-R project.
4. Only then attack the exact input domain feeding CC0 and stage-order ambiguities.
