# M11-P Category 42 Leica Chroma Suppress consumer proof

- exact unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`
- R2YS base: `0x002c9b38`
- Category 42 descriptor count: `8`
- Category 42 flags: `0x206` for all eight maps
- Category 42 map size: `44 bytes` for all eight maps
- Category 42 saturation states: `[-3, -2, -1, 0, 1, 2, 3, 10]`
- Category 42 dependencies: ISO `0..200000` plus Saturation state

## Direct Leica selector evidence

- selector function: `0x01579cbc`
- `0x01579e14`: exact A32 `MOV r0,#42` before selector-side category handling.
- `0x01579e34`: exact A32 `MOV r0,#42` in the command/wait path.
- that path constructs command `0xbb06001d`.
- the send path constructs command `0xbb06001c` and sends a 16-byte control packet.
- selector dependency log runtime `0x42b89210` -> file `0x02788f8c` using relocation `0x40400284`.
- selector error log runtime `0x42b89234` -> file `0x02788fb0` using the same relocation.
- unique selector identity string cluster starts at `0x02788ef0` / `0x02788f1c` and explicitly names `E_IMG_MACRO_DRV_R2Y_CATEGORY_CsCo_R2Y6A` and `img_macro_drv_r2y_select_chroma_suppress_paraset`.

## Decision

**PRIMARY M11 CONSUMER EVIDENCE:** R2YS Category 42 is selected by Leica's `img_macro_drv_r2y_select_chroma_suppress_paraset` / `CsCo` path. The prior Category-42 -> Chroma Suppress identification is no longer merely structural inference.

The separate low-level Milbeaut receiver call into `Im_R2Y_Ctrl_Chroma_Suppress` remains a downstream trace target. This proof does not establish exact CSP arithmetic, clamp placement, or which values are active in each highlight regime. The renderer must remain frozen until those semantics are established.
