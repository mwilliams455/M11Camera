# M11 Reference Renderer

This directory contains the recovered firmware-derived Leica M11-P reference renderer used in the earlier project work.

## Status

The renderer is a **forensic working model**, not a proven bit-exact Leica still pipeline and not yet a Xiaomi sensor profile.

Current assumed order:

```text
normalized scene-linear M11 working RGB
  -> CC0 (candidate Q9 matrix)
  -> 1024-point Q12 tone family
  -> CC1 (candidate Q9 matrix)
  -> Leica RGB-to-Y/Cb/Cr-like integer basis
  -> reconstructed 4096-point gamma on Y [ASSUMPTION]
  -> mode chroma scale
  -> inverse Y/Cb/Cr-like transform
  -> clamp
```

Recovered film-mode model:

| Mode | Contrast state | Chroma scale |
| --- | ---: | ---: |
| Natural | -1 | 1.00 |
| Standard | 0 | 1.15 |
| Vivid | +1 | 1.30 |

## Required forensic table directory

`leica_m11_reference_renderer.py` expects a directory containing:

```text
category3_CC0_candidate.json
category13_CC1_candidate.json
tone_q12_reconstructed_curves.csv
gamma_4096_high_nibble_first.csv
```

Run the structural validator before using a recovered table set:

```bash
python renderer/reference/validate_forensics_data.py /path/to/M11P_color_forensics_v0.3
```

Then generate diagnostics/reference cubes with:

```bash
python renderer/reference/leica_m11_reference_renderer.py \
  --data-dir /path/to/M11P_color_forensics_v0.3 \
  --out-dir /tmp/m11_reference
```

Python dependency: `numpy`.

## Important R0 constraints

- Do not treat CC0/CC1 as Xiaomi sensor matrices.
- Do not treat the current gamma placement as proven.
- Do not use the old Xiaomi LUTs to define the renderer architecture.
- Do not add scene-specific tuning while the stage order/input-space investigation is open.
- Do not commit Leica firmware binaries to this public repository.

The target architecture is a source adapter from Xiaomi RAW into a defined scene-referred interchange space, followed by a validated M11 target renderer.
