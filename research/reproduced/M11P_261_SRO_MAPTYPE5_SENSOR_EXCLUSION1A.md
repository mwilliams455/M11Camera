# M11-P 2.6.1 SRO MAPTYPE5 SENSOR EXCLUSION1A

Date: 2026-09-11
Firmware: Leica M11-P 2.6.1
Unpacked SHA256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Conclusion

`img/data/sro.bin` / resolver map type `5` is a sensor-readout / sensor-correction parameter family used by SRO-mode DPC/PDAF/SDC setup. It is **not evidence for the unresolved Leica colour/reference-basis transform** and must not be used to justify a RENDER1I colour-matrix change.

The previously recorded 132-byte object containing M11 DNG ColorMatrix1, ColorMatrix2, and a third 3x3 integer matrix must therefore be traced independently under a neutral identity (`COLOR132` / `OBJECT132`). It must not be called an SRO colour object merely because the SRO family was previously under investigation.

RENDER1H remains frozen.

## 1. SRO parameter-manager identity

The image-parameter global base is `0x43379A34`.

The current and default SRO slots are:

- current SRO pointer: `0x43379A44` (`base + 0x10`)
- default SRO pointer: `0x43379A50` (`base + 0x1C`)

The generic parameter switch begins at `0x0178C3D0`. Its SRO getter case at `0x0178C488` returns current SRO when present and otherwise falls back to default SRO.

The resolver `0x0178C89C` loads the first word of the request object immediately before calling the generic switch:

```asm
ldr r0, [request, #0]
bl  0x0178C3D0
```

Therefore request offset `+0x00` is the map type.

The switch table establishes:

- SRO = map type `5`
- R2YS = map type `8`

This is an architectural separation: the proven R2YS photographic resources (CC0/CC1/Cat24/Cat42 and related R2Y resources) do not silently imply SRO map-type-5 use.

## 2. Proven production SRO request

A whole production-request scan recovered one statically proven type-5 request and twenty-three type-8 R2YS positive controls.

The type-5 request is built by function `0x0175DE14`:

```asm
0x0175DE9C: mov r3, #5
0x0175DEA0: str r3, [fp, #-0x84]
...
0x0175DFBC: sub r3, fp, #0x84
0x0175DFC0: mov r0, r3
0x0175DFC4: bl  0x0178D0A8
```

Thus `0x0175DFC4` is a proven live request for SRO map type 5.

## 3. Function semantics are sensor/DPC/PDAF, not colour

The exact firmware strings referenced by the `0x0175DE14` region identify its domain directly:

- `IMG:(sro) (dpc): av-value from settings`
- `IMG:(sro) (dpc): found no dpc - disable dpc`
- `IMG:(sro) (dpc): found dpc - enable!`
- `IMG:(sro) (sdc-pdaf): no-pdaf-memory - disable pdaf!`
- `IMG:(sro) (sdc-pdaf): found no pdaf-window - disable pdaf!`
- `IMG:(sro) (sdc-pdaf): stripe has no pdaf-pixel - disable pdaf!`
- `IMG:(sro) %s - no pdaf-parameter for this sro-mode - disable!`
- `img_macro_if_sro_get_sdc_pdaf`

The immediately following separate function at `0x0175E0B0` is also explicitly SRO/PDAF infrastructure, with strings including:

- `IMG:(sro) %s - no pdaf-window for this sro-mode`
- `img_macro_if_sro_get_pdaf_parameter`
- `IMG:(sro) %s - no pdaf-stripe-window for this sro-mode`
- `img_macro_if_sro_get_pdaf_stripe_parameter`

The direct caller family also contains:

- `IMG:(sro) ff (black-image) disabled!`
- `IMG:(sro) sdc disabled!`
- `IMG:(sro) dpc disabled!`
- `IMG:(sro) pdaf disabled!`

These identifiers place this SRO path in sensor/image-acquisition correction, not in the photographic colour-rendering stack.

## 4. Returned SRO object is validity-gating in `0x0175DE14`

After the type-5 resolve call:

```asm
0x0175DFC4: bl  0x0178D0A8
0x0175DFC8: str r0, [fp, #-0xc]
0x0175DFCC: ldr r3, [fp, #-0xc]
0x0175DFD0: cmp r3, #0
...
0x0175E040: ldr r3, [fp, #-0xc]
0x0175E044: str r3, [fp, #-0x14]
```

The helper checks the resolved pointer for validity. Within the actual function boundary ending at `0x0175E0AC`, no matrix/coefficient data are read from the resolved SRO object.

The output values constructed afterward come from the separate input/context pointer saved at `fp-0x90`, including its `+0x58` subobject:

```asm
0x0175E060: ldr r3, [fp, #-0x10]
0x0175E064: ldr r3, [r3, #0x58]
0x0175E068: ldr r3, [r3]
...
0x0175E070: ldr r3, [fp, #-0x10]
0x0175E074: ldr r3, [r3, #0x58]
0x0175E078: ldr r3, [r3, #4]
```

So this specific proven SRO consumer uses SRO resolution as presence/availability gating for sensor-related configuration; it does not establish any colour transform.

## 5. Function-boundary correction

The original broad trace was intentionally bounded through `0x0175E4FC`, but `0x0175E0B0` is a new function prologue. The actual type-5 helper returns at:

```asm
0x0175E0A4: ldr r0, [fp, #-0x88]
0x0175E0A8: sub sp, fp, #4
0x0175E0AC: pop {fp, pc}
```

Therefore memory operations beginning at `0x0175E0B0` belong to the next PDAF helper and must not be attributed to `0x0175DE14`.

## 6. Rendering consequence

Closed:

- map type 5 is a live SRO family;
- SRO selection has current/default slots;
- a production SRO request exists;
- its proven consumer is sensor/DPC/PDAF infrastructure;
- this path provides no evidence for an M11 colour/reference-basis transform.

Not justified:

- identifying the independent 132-byte CM1/CM2/extra-matrix object as SRO;
- inserting the third 3x3 matrix into RENDER1H because of SRO;
- changing R2Y/B2R colour placement from this evidence.

## 7. Next investigation

Trace the independent 132-byte object under neutral name `COLOR132` / `OBJECT132`:

1. locate every exact occurrence of its CM1, CM2 and extra-matrix signatures;
2. identify the containing file/object and exact 33-word layout;
3. trace the loader/owner and runtime destination;
4. identify the production consumer and actual record-selection arithmetic;
5. determine whether that consumer is part of still-photo colour formation and where it lies relative to B2R/R2Y/gamma.

Only that consumer-path evidence can justify replacing or refining the provisional Android reference-basis bridge.
