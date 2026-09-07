# M11 Evidence Status

**Updated:** 2026-09-07

## Recovered and now committed

- M11/M11-P firmware decompression algorithm, recovered and parameterized as `tools/decompress_m11.py`.
- Firmware-derived Python working renderer at `renderer/reference/leica_m11_reference_renderer.py`.
- Leica Y/Cb/Cr-like integer basis used by the recovered renderer.
- Tone-luma weights used by the recovered renderer.
- Natural / Standard / Vivid contrast/chroma state model used by the recovered renderer.
- Structural validator for the historical four-file forensic table set.
- Proprietary-free synthetic decompressor regression tests.
- GitHub Actions Python validation workflow.

## Referenced by recovered code, but primary table files are not yet recovered

The historical renderer expects:

```text
M11P_color_forensics_v0.3/
  category3_CC0_candidate.json
  category13_CC1_candidate.json
  tone_q12_reconstructed_curves.csv
  gamma_4096_high_nibble_first.csv
```

The earlier work described these as:

- candidate CC0 matrix block;
- candidate CC1 matrix block;
- reconstructed 1024-point Q12 tone family;
- reconstructed 4096-point gamma table.

However, the four source table files did not surface in the accessible File Library recovery pass covering the original August 20–22 work window. Generated LUTs that depended on them do exist, but those outputs are regression controls rather than independent primary evidence.

Until the table directory is recovered or the values are deterministically re-extracted from a locally supplied firmware image, the repo should not label the numeric table contents as independently reproduced.

## Strong working model, not yet fully proven

```text
normalized scene-linear M11 working RGB
→ candidate CC0
→ 1024-point Q12 tone family
→ candidate CC1
→ Leica Y/Cb/Cr-like domain
→ reconstructed gamma on Y  [placement assumption]
→ mode chroma scaling
→ inverse transform
→ output/clamp
```

## Recovered mode model

| Mode | Contrast state | Chroma scale |
| --- | ---: | ---: |
| Natural | -1 | 1.00 |
| Standard | 0 | 1.15 |
| Vivid | +1 | 1.30 |

## Existing generated controls

The project archive contains numerous earlier M11/M11-P cubes, including full-reference linear cubes and Xiaomi/post-Adobe-curve bridge experiments. These are retained conceptually as regression references only.

They must not define:

- the M11 input space;
- exact stage order;
- gamma placement;
- final OETF;
- clipping/rounding semantics;
- Xiaomi source calibration.

## Genuine Leica validation material status

No genuine matching M11/M11-P DNG + in-camera JPEG pair was found in the currently searchable File Library during the 2026-09-07 recovery pass. A connected Dropbox search for `M11` also returned no matching asset.

This records current accessibility only; it is not a claim that such material never existed.

## Open R0-R1 validation targets

- recover/re-extract the four forensic table files;
- build a canonical table extractor with a manifest and stable hashes;
- exact colour space entering CC0;
- exact semantic output space of CC1;
- CC0/tone/CC1 stage order edges;
- gamma placement;
- final output OETF;
- clipping/headroom points;
- integer precision and rounding;
- output gamut conversion;
- ISO-conditional target processing;
- any still-path local/spatial processing relevant to M11 rendering.

## Source-side Xiaomi work to reuse

Once the M11 target renderer is structurally closed, Xiaomi RAW should enter through an independent physical-camera source adapter into a defined scene-referred interchange space. Cobalt and the historical M11 LUTs are not architectural dependencies.

Initial port target remains:

```text
Xiaomi 15 Ultra main RAW
→ Xiaomi source adapter
→ scene-referred interchange space
→ M11 expected input bridge
→ validated M11 Standard renderer
→ output
```

## Required local/private evidence to add when available

- Leica M11-P 2.6.1 source firmware for local extraction/reproducibility checks; do not commit it to this public repo;
- or the original complete `M11P_color_forensics_v0.3` directory;
- genuine Leica M11/M11-P DNG + matching in-camera JPEG pairs;
- Xiaomi 15 Ultra main-camera RAW regression set plus Camera2/DNG metadata sidecars.

## R0 exit criteria

R0 is complete when:

1. the firmware-derived table assets are reproducible and provenance-tagged;
2. genuine M11 DNG metadata is parsed and compared with the internal working model;
3. the M11 input domain is explicitly defined;
4. a deterministic Standard renderer exists with no scene-specific tuning;
5. a source-adapter contract exists for Xiaomi RAW;
6. LUTs and Cobalt are not required by the renderer architecture.

See `R0_RECOVERY_AUDIT.md` for the evidence classification rules used during recovery.
