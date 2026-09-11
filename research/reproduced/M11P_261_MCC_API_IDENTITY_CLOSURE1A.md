# M11-P 2.6.1 — MCC API identity closure 1A

## Status

Closed from the exact M11-P 2.6.1 unpacked firmware plus the already-closed MCC hardware writer at `0x01B2D324`.

## Writer

- entry: `0x01B2D324`
- first architectural return: `0x01B60320`
- ABI observed directly in the prologue:
  - `r0` = pipe number (`0..2`)
  - `r1` = pointer to the full multi-axis control object

## Leica assertion-string identity

The function loads runtime string pointers:

- `0x42B780E0`
- `0x42B7811C`

Their spacing is exactly `0x3C` bytes.

In the exact unpacked Leica firmware, the corresponding file strings are:

- file `0x030CF910`: `Im_R2Y_Ctrl_Multi_Axis error. r2y_ctrl_multi_axis = NULL`
- file `0x030CF94C`: `Im_R2Y_Ctrl_Multi_Axis error. pipe_no>D_IM_R2Y_PIPE12`

Both are mapped by the same relocation delta:

`0x3FAA87D0`

Validation:

- `0x030CF910 + 0x3FAA87D0 = 0x42B780E0`
- `0x030CF94C + 0x3FAA87D0 = 0x42B7811C`

Therefore `0x01B2D324` is specifically the Leica/Milbeaut API implementation:

`Im_R2Y_Ctrl_Multi_Axis(pipe_no, r2y_ctrl_multi_axis)`

This independently agrees with the complete `F_R2Y.MCC` register footprint and the 1,932-byte `CtrlMultiAxis` source-object layout already closed in `M11P_261_MCC_HARDWARE_WRITER_CLOSURE1A.md`.

## Nearby Leica API ordering

The same relocated firmware string region places the APIs in a coherent R2Y sequence:

`CC0 -> Multi_Axis -> BeforeTone -> Tone -> Gamma -> CC1`

Representative runtime strings:

- `0x42B77FF8`: `Im_R2Y_Ctrl_CC0_Matrix ...`
- `0x42B780E0`: `Im_R2Y_Ctrl_Multi_Axis ...`
- `0x42B78154`: `Im_R2Y_Ctrl_BeforeTone_Offset ...`
- `0x42B783E4`: `Im_R2Y_Ctrl_Tone ...`
- `0x42B78500`: `Im_R2Y_Ctrl_Gamma ...`
- `0x42B7868C`: `Im_R2Y_Ctrl_CC1_Matrix ...`

The string ordering is not used by itself to infer pixel-stage order; MCC placement remains independently closed by `R2YMODE.MCCSL = 0`.

## Invocation boundary

No direct ARM `B/BL`, raw little-endian absolute pointer, or MOVW/MOVT construction of `0x01B2D324` was found in the normal scanned code region.

Therefore the still-photo coefficient-source path must still be established independently. Likely possibilities include an IQ-bin/RDMA path, an indirect dispatch/API table, or another control-object producer that eventually supplies the same `CtrlMultiAxis` data.

## Renderer policy

**RENDER1H remains frozen.**

API identity and placement are closed, but Leica's actual MCC coefficient object has not yet been recovered. Do not add an MCC stage to the renderer from public/default coefficients or visual fitting.
