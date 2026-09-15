# M11 COLOR132 / ColorSpec dynamic CC0 -> R2Y hardware closure

Firmware basis: Leica M11-P 2.6.1 unpacked SHA256 `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`.

## Closed result

The dynamic 44-byte CC0 generated in ColorSpec is the CC0 consumed by the still-image R2Y hardware path. It is not a DNG-only metadata matrix and it is not an additional matrix stage to insert ahead of the existing CC0 stage.

The exact pointer/data chain is:

1. Current still-frame object is installed in global `0x43433774` by still controller `0x01790FAC` (live install `0x01794780`, fallback install `0x01795ADC`). The object is formed as a frame base plus `0x240`.
2. At `0x01791860` the still controller loads `r2 = *(0x43433774)`. At `0x01791878` it moves `r1 = r2` and calls `0x017B4EC4` at `0x01791884`.
3. `0x017B4EC4` stores incoming `r1` at `[fp-0x1C]` (`0x017B4ED4`). At `0x017B5068` it reloads that value into `r1` and calls `0x0178A3A0` at `0x017B5070`.
4. `0x0178A3A0` stores incoming `r1` at `[fp-0x0C]` and then writes it verbatim to global AAA state `0x43379928 + 0xFC` at `0x0178A3FC`.
5. AAA dispatcher later reads its state object and obtains `[state+0xFC]` at `0x016CEFDC`, moves it into `r0`, and calls CM `0x016EB010` at `0x016CEFE4`.
6. CM updates the fixed ColorSpec root `0x43430188`, then `0x016EB09C` materializes the ColorSpec results into that `r0` destination frame. Dynamic CC0 is copied from `ColorSpecRoot+0x28` to `frame+0x1F8` as a 44-byte record.
7. R2Y dispatcher `0x0176E75C` receives the same frame object as its third argument. It reads all nine 32-bit coefficient words from `frame+0x1F8...+0x218`, writes them as nine 16-bit hardware-control coefficients at per-pipe offsets `+0x40...+0x50`, and carries the low byte of the tenth field at `frame+0x21C` into control offset `+0x52`.
8. The already-established still R2Y ordering is `CC0 -> MCC -> gamma`.

Therefore:

`ColorSpec compute -> materialize dynamic CC0 into frame -> R2Y hardware CC0 -> MCC -> gamma`

is the firmware-faithful architecture.

## COLOR132 consequence

`R2Y_CC0_CM.bin` is 132 bytes = three 44-byte records. Evidence supports two calibration/illuminant matrix records plus a default CC0 seed. Record 3 must not be interpreted as a missing extra reference-basis transform. The runtime ColorSpec process computes the CC0 that is later materialized into the frame and consumed by hardware.

## Selector correction

The output-space selector table ordering was previously inferred incorrectly from a fallback/debug message. Matrix fingerprinting shows:

- selector 0 second matrix: canonical D50 PCS/XYZ -> linear Adobe RGB (1998)
- selector 1 second matrix: canonical D50 PCS/XYZ -> linear sRGB

The enum/table order must therefore be derived from firmware logic rather than the fallback text.

## Implementation rule

Do **not** add ColorSpec as another matrix before the existing renderer CC0. The Android renderer should ultimately reproduce Leica's ColorSpec/WB calculation and use its result as the dynamic CC0 for the existing CC0 stage. The current RENDER1H renderer remains frozen until the exact dynamic-CC0 arithmetic/domain is resolved.

## Next research seam

Reverse the arithmetic that produces `ColorSpecRoot+0x28` and its tenth control field. Primary targets:

- `0x016EBE14` and its callees
- all writers/read-modify-writers of `0x43430188 + 0x28 ... +0x50`
- dependence on WB / temperature / tint / calibration illuminant interpolation
- selector/output-space influence on the final CC0
- finite-precision representation and rounding before the R2Y 16-bit control copy
