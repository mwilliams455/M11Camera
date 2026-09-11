# M11-P 2.6.1 SRO MAPTYPE5 SENSOR PATH1A

Date: 2026-09-11
Firmware: Leica M11-P 2.6.1
Unpacked SHA256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Conclusion

Resolver map type `5` is the live SRO family. The production type-5 consumer closed so far is sensor/image-acquisition infrastructure used by SRO-mode DPC/PDAF/SDC setup. **That specific consumer does not justify a Leica colour/reference-basis transform or any RENDER1I matrix change.**

However, a later neutral firmware scan shows that the exact 132-byte object containing M11 DNG ColorMatrix1, ColorMatrix2 and the unresolved third 3x3 matrix begins immediately after the static `img/data/sro.bin` filename entry. The object is therefore strongly associated with the embedded SRO resource at the static-layout level. The earlier stronger interpretation that SRO and COLOR132 were independent is withdrawn.

What remains unproved is whether the matrix fields inside that SRO-associated payload are consumed on the still-photo colour path, and if so where. Static adjacency is not runtime placement evidence.

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

This remains an architectural separation: proven R2YS photographic resources such as CC0/CC1/Cat24/Cat42 are selected through type 8, not type 5.

## 2. Proven production SRO request

A production-request scan recovered one statically proven type-5 request and twenty-three type-8 R2YS positive controls.

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

## 3. Proven type-5 consumer semantics are sensor/DPC/PDAF

The exact firmware strings referenced by `0x0175DE14` identify its domain directly:

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

The caller family also contains:

- `IMG:(sro) ff (black-image) disabled!`
- `IMG:(sro) sdc disabled!`
- `IMG:(sro) dpc disabled!`
- `IMG:(sro) pdaf disabled!`

These identifiers close this particular consumer as sensor/image-acquisition correction.

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

Within the actual function boundary ending at `0x0175E0AC`, no matrix/coefficient data are read from the resolved SRO object. Output values later constructed in this helper come from a separate input/context pointer saved at `fp-0x90`, including its `+0x58` subobject.

Therefore this consumer establishes SRO availability for sensor configuration, not use of the embedded colour matrices.

## 5. Function-boundary correction

The original broad trace extended through `0x0175E4FC`, but `0x0175E0B0` is a new function prologue. The actual type-5 helper returns at:

```asm
0x0175E0A4: ldr r0, [fp, #-0x88]
0x0175E0A8: sub sp, fp, #4
0x0175E0AC: pop {fp, pc}
```

Memory operations beginning at `0x0175E0B0` therefore belong to the next PDAF helper.

## 6. New static COLOR132 association with `sro.bin`

A neutral signature scan of the exact firmware finds one contiguous little-endian 132-byte structure at file `0x002C9A98` and no copies in either ROMFS.

Its layout is:

- record 1 @ `0x002C9A98`: M11 DNG ColorMatrix1 Q12, marker `12`, temperature `2850`
- record 2 @ `0x002C9AC4`: M11 DNG ColorMatrix2 Q12, marker `12`, temperature `6807`
- record 3 @ `0x002C9AF0`: matrix `[212,-165,-71,-73,676,85,-27,174,285]`, marker `0`, temperature `6807`

Immediately before this object, firmware contains the literal filename:

`img/data/sro.bin`

Immediately after the 132-byte object are entries for:

- `img/data/R2Y_CC0_CM.bin`
- `img/data/r2y.bin`

This makes the embedded COLOR132 block strongly SRO-associated in the static resource catalog. It does **not** yet prove that the third matrix is applied to image RGB, nor its scale/placement.

## 7. SRO slot mutators do not close initialization

Current-SRO mutator `0x0178D8AC` and default-SRO mutator `0x0178D98C` both:

1. load the existing slot;
2. free it when non-null;
3. clear the slot;
4. perform file write/delete handling through generic helpers.

They do not reveal the startup/default loader that populates `+0x10` or `+0x1C`. Therefore the required bridge from embedded `sro.bin`/COLOR132 data to the runtime SRO object remains the **load/reload path**, not these mutators.

## 8. Rendering consequence

Closed:

- map type 5 is the live SRO family;
- current/default SRO selection is proven;
- a production type-5 consumer is proven;
- that consumer is DPC/PDAF/SDC sensor infrastructure and does not read matrix coefficients;
- COLOR132 is statically associated with the embedded `img/data/sro.bin` catalog entry.

Not yet justified:

- calling record 3 an active still-render matrix;
- assuming marker `0` means a particular fixed-point scale;
- inserting record 3 into RENDER1H;
- assigning it relative to B2R, R2Y, CC0/CC1 or gamma.

## 9. Next investigation

Trace the SRO load/reload path, especially `0x0178C174` and `0x0178C24C`, which are invoked after current/default SRO parameter changes. Determine:

1. how current/default SRO objects are loaded and stored in `0x43379A44/0x43379A50`;
2. the runtime object layout and payload offset;
3. whether the embedded 132-byte colour block is copied/parsed into that runtime object;
4. which production functions read the matrix records;
5. whether any such reader participates in still-photo colour formation.

Only that consumer-path evidence can justify refining the provisional Android reference-basis bridge.
