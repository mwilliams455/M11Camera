# M11-P 2.6.1 R2YMODE MCCSL PLACEMENT CLOSURE1A

Date: 2026-09-11
Firmware: LEICA_M11-P_2.6.1.FW
Updater SHA-256: `0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`
Unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Result

Leica M11-P 2.6.1 programs:

```text
R2YMODE.MCCSL = 0
```

Public Milbeaut semantics are:

```text
MCCSL = 0 -> multi-axis colour correction after CC0
MCCSL = 1 -> multi-axis colour correction after gamma
```

Therefore the relevant M11-P R2Y pipeline uses multi-axis colour correction **after CC0 and before gamma**.

## Primary firmware chain

The true Leica F_R2Y common-control setter is:

```text
0x01B1CDA4
```

It uses the same per-pipe R2Y base table (`0x43201224`) independently pinned by the Cat24 YC hardware-programmer trace. The MCCSL write is sourced from control byte `+0x67`:

```asm
0x01b1d384: ldr  r2, [fp, #-0x14]
0x01b1d388: ldrb r2, [r2, #0x67]
0x01b1d38c: and  r2, r2, #1
0x01b1d394: add  r3, r3, #0x4000
0x01b1d39c: lsl  r2, r2, #4
0x01b1d3a0: ldr  r1, [r3, #0x94]
0x01b1d3a4: bic  r1, r1, #0x10
0x01b1d3a8: orr  r2, r1, r2
0x01b1d3ac: str  r2, [r3, #0x94]
```

Adjacent control fields line up with the public R2YMODE bit layout:

```text
control +0x65 -> YCFBYP, bit 0
control +0x66 -> YCFPDD, bit 1
control +0x67 -> MCCSL,  bit 4
control +0x68 -> MCC1BM, bit 5
```

The setter has one direct Leica caller at:

```text
0x0176FE60
```

That caller creates and zero-initializes a local `0x74`-byte common R2Y control object and populates it through:

```text
0x0172C19C
```

The builder explicitly writes the four relevant bytes:

```asm
0x0172c1cc: ldr  r3, [fp, #-0x10]
0x0172c1d0: mov  r2, #0
0x0172c1d4: strb r2, [r3, #0x65]

0x0172c1d8: ldr  r3, [fp, #-0x10]
0x0172c1dc: mov  r2, #1
0x0172c1e0: strb r2, [r3, #0x66]

0x0172c1e4: ldr  r3, [fp, #-0x10]
0x0172c1e8: mov  r2, #0
0x0172c1ec: strb r2, [r3, #0x67]

0x0172c1f0: ldr  r3, [fp, #-0x10]
0x0172c1f4: mov  r2, #0
0x0172c1f8: strb r2, [r3, #0x68]
```

The builder does not subsequently overwrite `+0x67` in the recovered function. The MCCSL value is therefore a direct firmware constant for this path, not inferred from image appearance or register-address order.

## Closed values

```text
YCFBYP = 0
YCFPDD = 1
MCCSL  = 0
MCC1BM = 0
```

## Renderer consequence

This closes the stage-location question only. It does **not** justify mutating the validated RENDER1H Cat42 implementation.

The current renderer does not yet expose a distinct recovered Milbeaut multi-axis MCC stage. The correct next research target is to identify the Leica R2YS resource family and arithmetic feeding `F_R2Y.MCC`, then implement any future MCC candidate at the now-proven location:

```text
CC0 -> MCC -> gamma
```

RENDER1H remains frozen until that MCC resource/arithmetic chain is independently closed enough for a separate candidate.
