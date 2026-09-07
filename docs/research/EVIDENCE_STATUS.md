# M11 Evidence Status

## Directly recovered / existing forensic assets

- Leica M11-P 2.6.1 firmware extraction tooling exists in prior project work.
- Candidate CC0 matrix block.
- Candidate CC1 matrix block.
- Reconstructed 1024-point Q12 tone family.
- Leica Y/Cb/Cr-like integer matrix.
- Reconstructed 4096-step gamma table.
- Natural / Standard / Vivid contrast and chroma state model.
- Existing Python reference renderer.

## Strong working model, not yet fully proven

```text
linear M11 working RGB
→ CC0
→ tone
→ CC1
→ Leica Y/Cb/Cr-like domain
→ gamma on Y
→ mode chroma scaling
→ inverse transform
→ output
```

## Open / R0-R1 validation targets

- exact colour space entering CC0;
- exact semantic output space of CC1;
- stage order edges;
- gamma placement;
- final output OETF;
- clipping/headroom points;
- integer precision and rounding;
- output gamut conversion;
- ISO-conditional target processing;
- any still-path local/spatial processing relevant to M11 rendering.

## Required local evidence to locate or add

- complete `M11P_color_forensics_v0.3` extraction set;
- `leica_m11_reference_renderer.py`;
- `decompress_m11.py` and extraction tooling;
- source firmware available locally for reproducibility checks (do not commit proprietary firmware to this public repo);
- genuine Leica M11/M11-P DNG + matching JPEG pairs;
- Xiaomi 15 Ultra main-camera DNG regression set;
- Xiaomi source-calibration metadata / sidecars;
- optional old accepted M11 LUTs and DCPs as comparison controls only.

## R0 exit criteria

R0 is complete when:

1. recovered assets are reproducible and provenance-tagged;
2. genuine M11 DNG metadata is parsed;
3. the M11 input domain is explicitly defined;
4. a deterministic Standard renderer exists with no scene-specific tuning;
5. LUTs and Cobalt are not required by the renderer architecture.
