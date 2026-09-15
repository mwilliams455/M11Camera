# M11-P 2.6.1 — Category25 / YBLEND inactive closure 1A

Date: 2026-09-15

## Result

Category 25 is closed as **inactive for the recovered M11-P 2.6.1 still R2Y configuration**. No photographic-renderer stage needs to be added for it.

The exact Category25 resource contains one dependency-free four-byte map:

- descriptor index: `8`
- flags: `0x2`
- absolute map offset: `0x002CE24C`
- size: `4`
- SHA-256: `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`
- payload: `00 00 00 00`
- uint16 LE: `[0, 0]`

## Live consumer chain

The already-closed YC wrapper at `0x0172DFC0` first builds the nine Category24 YC coefficients, then explicitly requests selector/category `0x19` at `0x0172E1B4`:

```text
0x0172E1B4  mov  r3, #0x19
0x0172E1B8  str  r3, [fp, #-0x74]
0x0172E1BC  sub  r3, fp, #0x7c
0x0172E1C0  mov  r0, r3
0x0172E1C4  bl   0x0178D0A8
```

On a successful lookup it reads exactly the two uint16 words from that returned four-byte payload and narrows them to the two one-byte fields appended after the YC coefficients:

```text
0x0172E1FC  ldr  r3, [fp, #-0xc]
0x0172E200  ldrh r3, [r3]
...
0x0172E20C  strb r3, [fp, #-0xe]

0x0172E210  ldr  r3, [fp, #-0xc]
0x0172E214  ldrh r3, [r3, #2]
...
0x0172E220  strb r3, [fp, #-0xd]
```

The complete local YC control structure is then passed to the hardware setter:

```text
0x0172E22C  sub  r3, fp, #0x20
0x0172E230  mov  r0, r2
0x0172E234  mov  r1, r3
0x0172E238  bl   0x01B624AC
```

## Hardware identity

The public Socionext/Milbeaut `R2yCtrlYcc` ABI independently identifies the two fields following the nine signed YC coefficients as:

- `yBlendRatio`
- `ybBlendRatio`

The live Leica setter `0x01B624AC` consumes the corresponding bytes at control offsets `+0x12` and `+0x13` and programs the two fields in the R2Y `YBLEND` register at hardware offset `+0x120`:

```text
0x01B62B24  ldr  r2, [fp, #-0xc4]
0x01B62B28  ldrb r2, [r2, #0x12]
...
0x01B62B3C  ldr  r1, [r3, #0x120]
...
0x01B62B48  str  r2, [r3, #0x120]

0x01B62B5C  ldr  r2, [fp, #-0xc4]
0x01B62B60  ldrb r2, [r2, #0x13]
...
0x01B62B78  ldr  r1, [r3, #0x120]
...
0x01B62B84  str  r2, [r3, #0x120]
```

The first ratio occupies low bits of `YBLEND`; the second is shifted into the next byte field. The public API allows nonzero ratios, but Leica's sole Category25 map programs both ratios to zero.

## Closure

The consumer identity and value chain are therefore complete:

`R2YS Category25 [0,0] -> YC wrapper selector 0x19 -> local YC control fields -> R2Y YBLEND ratios -> [0,0]`

For this firmware/configuration, Category25 cannot alter the still image because both programmed blend ratios are zero.

Accordingly:

- do **not** add a Y/Yb blend operation to RENDER1H/RENDER1I;
- do **not** infer or tune a YBLEND formula photographically;
- keep Category24 YC conversion and the already-closed gamma/Category42 placement unchanged;
- if a later Leica firmware contains nonzero Category25 values, that firmware would require a separate arithmetic investigation before porting the effect.

## Reproduction

Probe:

`tools/trace_m11_cat25_yblend.py`

Workflow:

`.github/workflows/r2a-m11-cat25-yblend.yml`

Validated GitHub Actions run:

`34954670166`

The run completed successfully against the canonical unpacked M11-P 2.6.1 SHA-256:

`28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`
