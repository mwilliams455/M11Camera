# APK1A RAW decode parity contract

Date: 2026-09-09

## Status

This document freezes the RAW decode/demosaic boundary used by the current controlled Xiaomi -> M11 Python oracle. It is a parity contract, not permission to change photographic rendering.

The Android renderer must not silently substitute Android framework DNG/JPEG colour processing for this stage. Until a decoder meets this contract, APK1A remains a metadata/source-transform diagnostic shell.

## Authoritative current oracle

Source: `tools/render_xiaomi_m11_controlled.py::decode_camera_rgb`

Backend:

- `rawpy` / LibRaw
- demosaic algorithm: AHD
- output: 3-channel `uint16`
- output colour space: raw camera RGB

Exact oracle parameters:

```text
demosaic_algorithm = AHD
half_size = policy below
four_color_rgb = false
use_camera_wb = false
use_auto_wb = false
user_wb = [1, 1, 1, 1]
output_color = raw camera RGB
output_bps = 16
no_auto_scale = false
no_auto_bright = true
adjust_maximum_thr = 0.0
bright = 1.0
highlight_mode = Clip
gamma = (1.0, 1.0)
```

No highlight reconstruction, local processing, camera colour conversion, creative look, or additional white balance is permitted at this boundary.

## Decode-scale policy

The Python oracle currently defines:

- `full`: full LibRaw AHD output
- `half`: LibRaw half-size output
- `auto`: use half-size only when the visible RAW long edge is greater than 6000 pixels

Android must report which mode was requested and which mode was actually used. A different implicit downscale policy is not parity.

## Normalization boundary

The oracle returns `uint16` camera RGB from LibRaw and the renderer then converts it to floating point using exactly:

```text
camera_rgb = rgb16 / 65535.0
```

The DNG live neutral is **not** applied as a second RGB white-balance multiplier. It is consumed by the DNG dual-illuminant source transform.

The oracle's intended decode normalization is:

- LibRaw black subtraction
- deterministic theoretical sensor-maximum scaling to 16-bit output
- content-dependent maximum adjustment disabled (`adjust_maximum_thr=0.0`)
- no auto-bright

An Android port must not replace this with frame-dependent normalization.

## Metadata/diagnostics that must survive the port

For every decoded DNG, record at least:

- decoder/backend build identity
- full vs half-size mode
- source visible dimensions
- output dimensions and type
- CFA pattern
- LibRaw/camera colour descriptor or equivalent channel-order record
- black level per channel
- DNG white level
- camera white level per channel when present
- number of RAW colour channels
- highlight policy
- WB policy
- normalization policy

APK1A now also reads Exif ISO independently so Category-13 CC1 selection is based on the recorded capture ISO rather than a guessed band.

## Required parity comparison

Use the **same DNG bytes** as input to Python and Android. Compare before any DNG source matrix or M11 rendering stage.

Required outputs/metrics:

1. output width/height and channel count
2. channel ordering
3. per-channel min/max/mean and p01/p50/p99
4. fraction at zero and fraction at 65535
5. absolute pixel error distribution per channel
6. spatial error map, with borders reported separately from the interior
7. hashes of the exact input DNG and produced RGB16 buffers

No numerical pass threshold is declared yet. It must be set from measured same-DNG behavior, not chosen in advance to make an implementation pass.

## Implementation direction

Preferred order:

1. **JNI LibRaw path using AHD** — highest probability of reproducing the oracle semantics.
2. Independent AHD implementation — acceptable only if measured parity is demonstrated.
3. Android framework/preview decode — not acceptable as the RAW parity oracle because colour/WB/tone behavior is not under the same contract.

The JNI boundary should be narrow. A future native decoder should accept a DNG file descriptor/path plus the explicit scale mode and return deterministic RGB16 plus diagnostics. It must not contain M11 matrices, tone, gamma, saturation, or third-SRO behavior.

## Promotion rule

Do not wire RAW pixels into `M11ReferenceRendererCore` until:

- Android <-> Python renderer stage parity is green;
- ISO/CC1 selection is evidence-driven;
- the RAW decoder has same-DNG parity evidence against this contract.

The unresolved third SRO matrix remains outside this work and must stay inactive.
