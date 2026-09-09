# Xiaomi 15 Ultra -> M11 Controlled Renderer Validation

**Status:** R3 device-validation harness  
**Branch:** `research/m11-r0-evidence-input-space`

This procedure is the next project milestone after closing the broad gamma-loader investigation. It is deliberately a controlled offline path, not a visual-tuning workflow.

## Pipeline under test

```text
Xiaomi 15 Ultra DNG
  -> linear LibRaw/rawpy camera-RGB demosaic, unity WB
  -> DNG dual-illuminant camera RGB -> XYZ D50
  -> provisional M11 Standard-A reference-basis bridge
  -> frozen M11 reference renderer
       CC0 -> tone -> CC1 -> YC -> gamma(Y) -> mode chroma -> inverse YC -> clamp
  -> high-quality JPEG + JSON diagnostics
```

The harness does **not** add HDR, local tone mapping, highlight reconstruction, Cobalt, a visual correction LUT, or an extra source white-balance stage.

The current gamma placement remains the frozen provisional placement A. This tool is not permission to reopen or retune gamma placement by eye.

## Tool

```text
tools/render_xiaomi_m11_controlled.py
```

### Dependencies

Python packages:

```bash
python -m pip install numpy rawpy Pillow
```

System dependency:

```text
ExifTool
```

ExifTool is used only to extract DNG metadata deterministically. `rawpy`/LibRaw is used for a linear camera-RGB demosaic with unity WB, raw output colour space, no auto brightening, linear gamma and clipped highlights. The project source adapter then performs the Xiaomi colour/white-point transform exactly once.

## Firmware table gate

The public repository intentionally does not contain Leica firmware binaries. Before rendering, produce or recover the canonical forensic table directory and validate it:

```bash
python renderer/reference/validate_forensics_data.py /path/to/M11P_color_forensics_v0.3
```

The controlled runner requires these four files:

```text
category3_CC0_candidate.json
category13_CC1_candidate.json
tone_q12_reconstructed_curves.csv
gamma_4096_high_nibble_first.csv
```

Their SHA256 hashes are copied into every diagnostics JSON.

## First main-sensor render

```bash
python tools/render_xiaomi_m11_controlled.py \
  INPUT.DNG \
  --mode standard \
  --bridge dng-native-v1 \
  --data-dir /path/to/M11P_color_forensics_v0.3 \
  --physical-camera-id main \
  --out OUTPUT_M11_STANDARD.jpg \
  --diag OUTPUT_M11_STANDARD.json
```

`--physical-camera-id` is a user/capture label for the offline test. The diagnostics do **not** claim Camera2 physical-result association is proven merely because that label was supplied.

### Decode scale

Default:

```text
--decode-scale auto
```

In `auto`, DNGs whose visible long edge exceeds 6000 pixels use LibRaw half-size decoding; smaller DNGs stay at native size. This keeps 50 MP main-sensor captures near a practical validation resolution while preserving native resolution for already-binned/12 MP inputs.

For a final full-resolution check:

```text
--decode-scale full
```

For an explicit half-resolution check:

```text
--decode-scale half
```

The actual decision and output dimensions are recorded in JSON.

## Historical Xiaomi main characterization check

The runner compares the current DNG's static source metadata against:

```text
research/xiaomi/xiaomi15ultra_main_native_source_characterization_v1.json
```

The historical values are **not used for rendering**. They are only a continuity diagnostic.

The JSON reports:

- calibration-illuminant match;
- ColorMatrix1 maximum absolute delta;
- ColorMatrix2 maximum absolute delta;
- ForwardMatrix1 maximum absolute delta;
- ForwardMatrix2 maximum absolute delta;
- aggregate `historical_main_characterization_match`.

To fail closed when a supposed main-sensor capture no longer matches the recorded static characterization:

```text
--strict-main-characterization
```

A metadata match supports continuity with the earlier main-sensor audit. It does not independently prove the physical Camera2 result association.

## Diagnostics captured

Each render records at least:

- source DNG path and SHA256;
- user-supplied physical-camera label;
- camera make/model/unique model when available;
- lens model and focal length;
- ISO, shutter and aperture when present;
- DNG black and white levels;
- `AsShotNeutral`;
- `ColorMatrix1/2`;
- `CameraCalibration1/2` or explicit identity-default status;
- `ForwardMatrix1/2`;
- calibration illuminants;
- LibRaw black/white/CFA information;
- source-transform interpolation factor;
- estimated scene white xy and McCamy CCT;
- full camera->XYZ-D50 transform;
- M11 XYZ-D50->Standard-A reference-basis matrix;
- M11 mode and every renderer stage toggle;
- gamma-placement status;
- firmware-table hashes;
- sampled per-stage channel statistics;
- output dimensions, JPEG settings and SHA256.

The sampled stage statistics cover:

```text
camera RGB
XYZ D50
M11 reference input
M11 output code values
```

For each stage the diagnostics record mean, min/max, p01/p50/p99, and fractions below 0 or above 1. These are intended to separate source-bridge failures from target-renderer failures before any visual tuning is considered.

## Output encoding policy

The frozen reference renderer already includes the reconstructed Leica gamma-on-Y stage. The controlled runner therefore **does not add an sRGB OETF** after the M11 renderer.

By default the JPEG is tagged with an sRGB ICC profile for deterministic ordinary viewing, but that tag is an output-container assumption, not new evidence that the exact Leica final output gamut/transfer is sRGB. The JSON records this explicitly.

To omit the ICC tag:

```text
--jpeg-profile none
```

## Renderer stage controls

Normal device validation should leave every stage enabled. The following switches exist only for bounded diagnostics:

```text
--disable-cc0
--disable-tone
--disable-cc1
--disable-gamma
--disable-chroma
```

There is intentionally no RGB-common gamma alternative in this runner. The bounded gamma-placement result was inconclusive and the canonical provisional placement must remain frozen unless genuinely new evidence appears.

## First capture set

Main sensor first. Capture matched DNG scenes covering:

1. daylight;
2. overcast;
3. indoor neutral light;
4. tungsten;
5. skin;
6. saturated colours;
7. a high-dynamic-range scene, with no HDR processing.

For the first pass, use Standard mode and keep exposure consistent. After the source bridge looks stable, render the same DNGs in Natural and Vivid as well.

## First validation questions

For every scene, inspect the JPEG together with its diagnostics JSON:

1. Is broad tonal density plausible?
2. Does the current DNG static metadata still match the historical main characterization?
3. Is camera-RGB -> XYZ D50 producing excessive negative or >1 values?
4. Is the M11 Standard-A reference bridge where gamut/headroom first becomes unstable?
5. Does tungsten fail before or after the M11 bridge?
6. Are hue errors stable across exposure changes?
7. Do Natural / Standard / Vivid separate plausibly without bridge changes?
8. Is gamma visually material compared with source-bridge uncertainty?
9. Which component dominates remaining error: source calibration, M11 input bridge, tone, gamma/output transfer, mode chroma, or WB metadata?

Do not respond to a bad sample by tuning CC matrices or inserting a LUT. Use the diagnostics to identify the first incorrect boundary, then run a bounded experiment on that boundary.
