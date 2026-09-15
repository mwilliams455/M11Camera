# M11 ColorSpec dynamic CC0 -> still R2Y hardware closure

Date: 2026-09-15
Firmware: Leica M11-P 2.6.1
Unpacked SHA256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`
Branch: `work/render1h-cat42yq3a-placement1a`

## Conclusion

The Leica ColorSpec dynamic CC0 record is not DNG-only metadata and is not an additional matrix ahead of the R2Y CC0. It is the still-image CC0 state consumed by the R2Y hardware path.

The pointer identity is closed end-to-end:

1. The still controller installs the active processing frame pointer in global `0x43433774`.
2. At `0x01791864`, that exact pointer is loaded from `0x43433774` into `r2`; at `0x01791878`, it is moved into `r1`; `0x01791884` calls `0x017B4EC4`.
3. `0x017B4EC4` stores incoming `r1` verbatim at local `[fp-0x1C]` (`0x017B4ED4`).
4. The same local is passed unchanged as `r1` at `0x017B5068` into the sole AAA-state constructor call at `0x017B5070 -> 0x0178A3A0`.
5. `0x0178A3A0` stores incoming `r1` verbatim to `0x43379928 + 0xFC` at `0x0178A3FC`.
6. The AAA queued consumer later obtains that state object and CM is called with `[state+0xFC]` as `r0` at `0x016CEFDC..0x016CEFE4`.
7. CM/ColorSpec writes its dynamic 44-byte CC0 record into that frame at `frame+0x1F8`.
8. The still R2Y dispatcher `0x0176E75C` reads `arg3+0x1F8..+0x218` and copies all nine CC0 coefficients into the per-pipe R2Y control block at offsets `+0x40..+0x50`; the tenth ColorSpec field at `+0x21C` contributes the CC0 shift/control byte at `+0x52`.
9. The established hardware ordering is `CC0 -> MCC -> gamma`.

Therefore the dynamic ColorSpec result and the still R2Y CC0 are the same frame-resident control state.

## Important corrections to earlier working assumptions

- `COLOR132` / `R2Y_CC0_CM.bin` record 3 is a default/seed CC0, not a separate reference-basis transform that should be multiplied in ahead of hardware CC0.
- The captured Category-3 CC0 values must not be treated as universally static if faithful Leica rendering is the goal; Leica computes frame-dependent CC0 through ColorSpec and then programs R2Y from that result.
- Do not add ColorSpec as another colour matrix in front of the existing CC0 implementation. That would double-apply the operation.
- Selector-table ordering must not be inferred from the debug fallback string. The traced selector matrices showed selector 0's output matrix matches canonical D50 XYZ -> Adobe RGB (1998), while selector 1's output matrix matches canonical D50 XYZ -> linear sRGB.

## Renderer policy

`RENDER1H` remains frozen. No photographic renderer change should be made until the ColorSpec dynamic-CC0 generator arithmetic and its fixed-point/quantization boundary are reproduced well enough to replace the current static-CC0 assumption deliberately.

## Next research target

Close the exact dynamic-CC0 generation path:

1. Identify the exact ColorSpec inputs selected for the still frame: illuminant selector, CM1/CM2, white-point / WB state, and any calibration/adaptation input.
2. Recover the matrix composition order used to produce the 3x3 dynamic CC0 at ColorSpec root `+0x28`.
3. Recover normalization, inversion, rounding, clamp and scale/shift selection.
4. Map the 44-byte ColorSpec CC0 representation to the nine 16-bit hardware coefficients plus shift/control byte used by R2Y.
5. Build a desktop parity function first and compare against known firmware-generated CC0 records before any APK renderer integration.

## Key addresses

- AAA state object: `0x43379928`
- current still-frame global: `0x43433774`
- AAA-state constructor: `0x0178A3A0`
- sole constructor caller: `0x017B5070` in `0x017B4EC4`
- still-controller call into constructor caller: `0x01791884`
- CM entry: `0x016EB010`
- AAA -> CM call: `0x016CEFE4`
- dynamic CC0 frame offset: `+0x1F8`
- R2Y dispatcher / CC0 bridge: `0x0176E75C`
