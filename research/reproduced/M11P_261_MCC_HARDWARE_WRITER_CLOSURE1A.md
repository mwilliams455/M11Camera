# M11-P 2.6.1 — F_R2Y.MCC hardware-writer closure 1A

## Status

Closed from exact M11-P 2.6.1 firmware plus the public Milbeaut R2Y register/`CtrlMultiAxis` ABI.

This is a hardware-stage closure only. It does **not** yet recover Leica's default MCC coefficient source or justify changing RENDER1H.

## Canonical source

- Leica updater SHA-256: `0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`
- unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Address-basis closure

The already-proven Leica common-R2Y/MCCSL writer selects `perPipeBase + 0x4000` and writes the public `R2YMODE` register. Public Milbeaut places `R2YMODE` at `0xC094`, so Leica's per-pipe origin corresponds to public `0x8000`.

Therefore:

- `perPipeBase + 0x1000` -> public `0x9000` -> `F_R2Y.MCC`
- `perPipeBase + 0x2000` -> public `0xA000` -> downstream R2Y edge/post-colour blocks
- `perPipeBase + 0x4000` -> public `0xC000` -> common R2Y block / `R2YMODE`

The `+0x2000` mapping is independently cross-checked by Leica writes at `+0x180/+0x184`, matching public `EGSMCTL/EGSMTT` at `0xA180/0xA184`.

## Closed Leica MCC writer

Pinned entry:

`0x01B2D324`

First architectural return in the linear routine:

`0x01B60320`

Span:

- `208892` bytes
- `0x32FFC` bytes
- `948` recognized writes to the `perPipeBase + 0x1000` MCC bank

No direct ARM `BL` caller to the exact entry was found in the scanned normal code region, so the upstream invocation is currently expected to be indirect/table-driven or to use a different entry thunk. That remains an upstream-source question, not a hardware-writer identity question.

## Public `CtrlMultiAxis` / hardware-family correspondence

The writer covers the complete public multi-axis colour-correction geometry in hardware order:

| Public family | Leica recognized writes |
| --- | ---: |
| MCYC | 9 |
| MCB boundaries | 16 |
| MCID packed selector words | 4 |
| MCKA | 45 |
| MCKB | 45 |
| MCKC | 45 |
| MCKD | 45 |
| MCKE | 45 |
| MCKF | 45 |
| MCKG | 45 |
| MCKH | 45 |
| MCKI | 45 |
| MCKJ | 45 |
| MCKK | 45 |
| MCKL | 45 |
| MCLA | 30 |
| MCLB | 30 |
| MCLC | 30 |
| MCLD | 30 |
| MCLE | 30 |
| MCLF | 30 |
| MCLG | 30 |
| MCLH | 30 |
| MCLI | 30 |
| MCLJ | 30 |
| MCLK | 30 |
| MCLL | 30 |
| blend-register tail | 19 recognized direct-base stores |

The MCK counts exactly match `5 x 3 x 3 = 45` signed conversion entries per colour area. The MCL counts exactly match `5 x 3 x 2 = 30` entries per area.

Representative hardware progression:

- MCID1..4: `+0x40/+0x44/+0x48/+0x4C`
- MCKA: `+0x080`
- MCKB: `+0x100`
- MCKC: `+0x180`
- ...
- MCKL: `+0x600`
- MCLA: `+0x680`
- ...
- MCLL: `+0x940`
- blend region continues through at least `+0x9B4`

This is not a category-number inference: the concrete Leica hardware writes match the public `F_R2Y.MCC` register layout and the public control-array dimensions.

## Early source-layout match

The writer's source accesses also begin with the public control-object layout:

- first 9 signed 16-bit source coefficients occupy 18 bytes (`0x00..0x11`) -> MCYC
- boundary source loads begin at `0x12` and continue through the next 32 bytes -> exactly 16 x 16-bit boundary entries
- subsequent selector/matrix source regions continue in the expected order

A naturally packed public `CtrlMultiAxis` is `1932` bytes (`0x78C`):

- MCYC: 18 bytes
- boundaries: 32 bytes
- area indices: 40 bytes
- MCK A-L: 1080 bytes
- MCL A-L: 720 bytes
- blend controls: 42 bytes

The exact upstream Leica object builder/source is the next investigation target.

## Placement consequence

Separate primary-firmware evidence already closed:

`R2YMODE.MCCSL = 0`

Public Milbeaut semantics define this as MCC **after CC0 and before gamma**.

Therefore the closed architectural order is:

`CC0 -> MCC -> gamma`

## Renderer policy

**Do not modify RENDER1H yet.**

The hardware stage and placement are now closed, but Leica's actual default MCC control values and the precise software arithmetic/quantisation required for an Android reproduction are not yet recovered. The next work is to trace the writer's indirect caller/control-object builder and recover those values from firmware evidence.
