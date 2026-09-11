# M11-P 2.6.1 — Cat27..40 edge-family exclusion 1A

## Status

Closed from exact M11-P 2.6.1 firmware. The Cat27 parent wrapper at `0x0172EC18` and its optional Cat28/30/32/34/36/38/40 resources are **not** the Multi-Axis Color Correction (MCC) coefficient source.

No renderer behavior is changed by this closure.

## Canonical image

- updater SHA-256: `0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`
- unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Wrapper behavior

The wrapper builds a resolver request with `type=8`, parent request/category `27`, then conditionally requests 28/30/32/34/36/38/40 according to flags in the returned parent object.

Those optional resources are passed to seven low-level table APIs with fixed transfer sizes `0x200`, `0x100`, `0x200`, `0x100`, `0x200`, `0x100`, and `0xDD` respectively.

## Exact Leica API identities

Primary-firmware error strings identify the consumers unambiguously:

| request | consumer | API identity |
| ---: | --- | --- |
| 28 | `0x01B6A024` | `Im_R2Y_Set_HighEdge_Scale_Table` |
| 30 | `0x01B6A250` | `Im_R2Y_Set_HighEdge_Step_Table` |
| 32 | `0x01B6A480` | `Im_R2Y_Set_MediumEdge_Scale_Table` |
| 34 | `0x01B6A6AC` | `Im_R2Y_Set_MediumEdge_Step_Table` |
| 36 | `0x01B6A8DC` | `Im_R2Y_Set_LowEdge_Scale_Table` |
| 38 | `0x01B6AB08` | `Im_R2Y_Set_LowEdge_Step_Table` |
| 40 | `0x01B6AD38` | `Im_R2Y_Set_MapScl_Table` |

The firmware strings also state each table's bounds checks and pipe validation, independently matching the transfer widths observed at the wrapper call sites.

## Consequence for MCC research

The closed Leica MCC hardware/API path remains:

`CC0 -> MCC -> gamma`

with `Im_R2Y_Ctrl_Multi_Axis` at `0x01B2D324` consuming a 1932-byte (`0x78C`) `CtrlMultiAxis`-layout object.

Cat27..40 does not supply that object or its MCK/MCL coefficient payload. These resources are an edge/sharpness family and must not be used to derive Leica color rendering.

## Next target

Trace producers of the structural `CtrlMultiAxis` prefix itself:

- 9 signed MCYC coefficients (18 bytes)
- 16 boundaries (32 bytes)
- 40 bytes of MCID/area-selection data
- followed by MCK A-L and MCL A-L

A candidate is promoted only when its object/data-flow geometry agrees with the closed `Im_R2Y_Ctrl_Multi_Axis` ABI. Category adjacency is no longer accepted as evidence.
