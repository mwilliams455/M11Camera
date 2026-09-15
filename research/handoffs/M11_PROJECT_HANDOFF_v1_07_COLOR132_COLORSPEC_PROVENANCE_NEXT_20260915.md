# M11 PROJECT HANDOFF v1.07 — COLOR132 / COLORSPEC PROVENANCE NEXT

Date: 2026-09-15
Project: M11Camera
Repository: mwilliams455/M11Camera
Primary research branch: `work/render1h-cat42yq3a-placement1a`
Branch head at handoff creation: `081511a6f049aaba212340d4db61b5f14c1949a6`
Renderer status: **RENDER1H CAT42YQ3A ORIENT1A remains frozen**
User direction: continue firmware-first until Leica pixel math is justified; do not visually tune the M11 renderer.

---

## 1. Current objective

Continue reverse-engineering Leica M11-P 2.6.1 until the remaining upstream colour-space / working-basis ambiguity is closed well enough to justify a real Android renderer change.

The immediate unresolved question is now:

> **What live Leica object feeds the ColorSpec / DNG colour-management routines around `0x016EB09C`, and does that object contain or derive the 3-record COLOR132 structure at `0x002C9A98`?**

Do not make another colour-restoration APK until this is answered.

---

## 2. Canonical firmware

Updater SHA256:

`0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`

Unpacked SHA256:

`28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

All firmware forensics should continue to verify these hashes before analysis.

---

## 3. Frozen renderer state

Validated renderer remains:

**RENDER1H CAT42YQ3A ORIENT1A**

Do not mutate this branch merely because a firmware object appears colour-related.

Closed/frozen downstream sequence still includes:

- Xiaomi/DNG source adapter
- M11 reference-basis bridge as currently implemented
- CC0
- tone
- CC1
- gamma
- Cat24 YC conversion
- Cat42 chroma suppress
- orientation handled by LibRaw in the corrected path

The current suspected weak link is **before / around the M11 reference-basis stage**, not CC0/CC1/gamma/Cat42.

---

## 4. Orientation issue — CLOSED

Recent experimental APKs reintroduced a double-orientation bug.

Observed:

- DNG Orientation = 6
- LibRaw already produced the oriented raster (`3072×4096`)
- Java then rotated again to `4096×3072`

Correct policy:

> **LibRaw owns orientation. Java must not rotate the rendered raster again.**

This fix worked on device.

Keep ORIENTFIX behaviour in future experimental builds.

---

## 5. Colour-restoration experiments — REJECTED

### COLORBACK1A

Experiment:

- preserved B2RWBPLACE1A
- disabled Cat42 chroma suppression only
- no arbitrary saturation multiplier

Result:

- colour still looked essentially unchanged
- therefore Cat42 was not the cause of the global muted colour

Conclusion:

> Do not remove Cat42 as a colour-restoration strategy.

### COLORRESTORE1A

Experiment:

- restored Cat42
- applied 1.30× luma-preserving chroma expansion after the full Leica renderer
- used Leica/Milbeaut luma weights

Result:

- orientation fixed
- colour still not materially restored

Conclusion:

> Do not keep escalating a final-stage saturation/chroma gain. The missing colour is upstream.

---

## 6. B2R investigation — important but WB is not the missing colour stage

The B2R path around `0x0170AF48` was identified as:

`img_macro_drv_b2r_set`

Key low-level APIs resolved:

- `0x01A66FCC` = `Im_B2R_Set_WB_Gain`
- `0x01A674E4` = `Im_B2R_Ctrl_Sensitivity`
- `0x01A677BC` = `Im_B2R_Ctrl_HighPassFilter`

The Leica frame object provides WB gains from:

- R = `+0x1AC`
- G = `+0x1AE`, duplicated to Gr/Gb
- B = `+0x1B0`

These values are populated from AWB state.

A real producer was found at `0x016DCEB0`:

- AWB source `0x4342F91C +0x4D8` → frame `+0x1AC`
- source `+0x4DC` → frame `+0x1AE`
- source `+0x4E0` → frame `+0x1B0`
- source `+0x4E4` → frame `+0x1B2`

The sole caller sits inside the AWB module and references exact Leica strings:

- `AWB: ca9_StartWhiteBalance() - white balance module not active`
- `img/calib/AWB.bin`

One level higher, the path is explicitly the AAA state sequence:

- `AAA: AWB started`
- `AAA: AWB finished ...`
- `AAA: CM started`

Therefore the B2R gain triplet is ordinary live per-shot AWB, not a hidden Leica creative-colour transform.

Android implication:

- LibRaw itself has camera WB disabled in the oracle
- `AsShotNeutral` is instead folded into the source-adapter matrix
- therefore blindly adding the Leica B2R WB gains again risks double-WB

B2R placement remains architecturally interesting, but **B2R WB is not the current best explanation for missing M11 colour**.

---

## 7. MCC / MultiAxis status

MCC hardware writer identity remains closed:

`0x01B2D324 = Im_R2Y_Ctrl_Multi_Axis(pipe_no, r2y_ctrl_multi_axis)`

Full control-object ABI:

- 1932 bytes / `0x78C`
- exactly matches public Milbeaut `CtrlMultiAxis`

RDMA address geometry:

- `0x42B66EB8 + pipe*0x7F4`
- `0x7F4` exactly matches public `CtrlRdmaMcycAddr` address-count geometry

However:

- whole-image direct caller scan found no direct production BL to `0x01B2D324`
- no complete static 0x78C MCC object
- 600-byte R2YS family was later identified as Cat27 edge/sharpness parent data, not hidden MCK/MCL
- no justified non-identity MCC payload has been recovered for Standard still rendering

Do not add MCC to RENDER1H without new direct evidence.

---

## 8. Cat27–40 family — CLOSED as edge/sharpness

The former 600-byte/MCC hypothesis is closed.

Requests 28/30/32/34/36/38/40 resolve to:

- HighEdge scale / step
- MediumEdge scale / step
- LowEdge scale / step
- MapScl

The large 600-byte family corresponds to Cat27 edge/sharpness parent resources and selector dimensions `0x10/0x11`.

Do not revisit these as colour transforms.

---

## 9. SRO runtime architecture — partially closed

Image-parameter global base:

`0x43379A34`

Current SRO slot:

`0x43379A44` (`base +0x10`)

Default SRO slot:

`0x43379A50` (`base +0x1C`)

Generic map switch:

`0x0178C3D0`

SRO getter case:

`0x0178C488`

Resolver:

`0x0178C89C`

Critical ABI closure:

```asm
ldr r0, [request, #0]
bl  0x0178C3D0
```

Thus `request +0x00` is the map type.

Closed map types:

- SRO = 5
- R2YS = 8

A production type-5 request is proven in function `0x0175DE14`:

```asm
0x0175DE9C: mov r3, #5
0x0175DEA0: str r3, [fp, #-0x84]
...
0x0175DFC4: bl 0x0178D0A8
```

That consumer is sensor-side DPC/PDAF/SDC infrastructure and does not itself justify a colour transform.

Important correction:

> SRO is not globally “irrelevant to colour.” The proven type-5 consumer is sensor-only, but the static COLOR132 object is tightly associated with the embedded `img/data/sro.bin` resource record.

---

## 10. SRO load/reload path — CLOSED farther than before

Current SRO loader:

`0x0178C174`

Default SRO loader:

`0x0178C24C`

Both use generic file loader:

`0x0178AC68`

The current loader references:

- filename `img/data/sro.bin`
- destination slot `0x43379A44`

The default loader references:

- filename `img/data/default_sro.bin`
- destination slot `0x43379A50`

The generic loader allocates the exact file size and reads file bytes directly into the published slot buffer.

Therefore the SRO slot pointer is the file buffer itself, not an intermediate parser object.

---

## 11. COLOR132 — exact static layout

Unique 132-byte little-endian object at:

`0x002C9A98`

It contains exactly three 44-byte records.

### Record 1 @ `0x002C9A98`

M11 DNG ColorMatrix1:

`[2358,-546,-66,-2488,6300,1785,-403,797,3504]`

followed by:

- marker/scale-like field = 12
- temperature = 2850

### Record 2 @ `0x002C9AC4`

M11 DNG ColorMatrix2:

`[1700,-326,-200,-2354,5409,974,-612,976,2276]`

followed by:

- marker/scale-like field = 12
- temperature = 6807

### Record 3 @ `0x002C9AF0`

Unresolved matrix:

`[212,-165,-71,-73,676,85,-27,174,285]`

followed by:

- marker/scale-like field = 0
- temperature = 6807

No second exact copy exists in the firmware or the two ROMFS images.

Static layout:

- end-side `img/data/sro.bin`
- 8-byte alignment
- COLOR132
- 4-byte `0x55` tail/padding
- then next resource entries including `img/data/R2Y_CC0_CM.bin` / `img/data/r2y.bin`

Do not call record 3 an active render matrix yet.

---

## 12. Resource-section grammar — NEW CLOSED STRUCTURE

Firmware contains real paired section tags:

- `DPCS ... DPCE`
- `R2YS ... R2YE`
- `ELFS ... ELFE`

Their relative-link fields resolve to repeated resource filenames at section boundaries.

Important consequence:

- the large DPC/SRO sensor block ends at `DPCE`
- COLOR132 sits **after** that end marker, adjacent to the repeated `sro.bin` resource entry
- therefore COLOR132 is SRO-associated at the resource-catalog level but is not simply part of the huge PDAF/DPC table body

This makes a small SRO calibration/header role plausible.

---

## 13. COLOR132 direct-pointer scans — negative but not dispositive

No direct A32 MOVW/MOVT references were found to:

- `0x002C9A98`
- `+0x2C`
- `+0x58`

under the obvious runtime/file address mappings.

This does **not** prove the object is unused.

Likely explanations include:

- loaded indirectly from `sro.bin`
- copied through parameter manager
- referenced through PC-relative/literal tables
- parsed into another live ColorSpec object

Do not interpret lack of direct pointer xrefs as DNG-only evidence.

---

## 14. DNG / ColorSpec trace — highest-value new lead

Workflow:

`R2A M11 COLOR132 DNG consumers`

Run:

`34599267271`

Result: success.

The scan exposed a dedicated Leica colour-management module around:

`0x016EB09C`

This module prints/handles DNG CM1/CM2 and calls ColorSpec operations including:

- `ca9_cm_ColorSpec_MapWhiteMatrix`
- `ca9_cm_ColorSpec_MatrixInterpolate`

The code naturally uses geometry matching two 44-byte-spaced matrix records (`0x2C`, `0x58`).

This is currently more important than the generic SRO consumer.

### Critical call boundary

Immediately before `0x016EB09C`:

`0x016EB088 -> 0x016EB09C`

Arguments observed:

- `r0 = sp + 0x20`
- `r1 = PC-relative pointer`
- `r2 = 0xDC94`

This is now the exact provenance seam to trace.

---

## 15. NEXT TASK — DO THIS FIRST

Do **not** build another APK yet.

Trace the call into `0x016EB09C` end-to-end.

Required substeps:

1. Decode the PC-relative `r1` argument at `0x016EB088`.
2. Reconstruct the `sp+0x20` object passed as `r0`.
3. Identify what `r2 = 0xDC94` represents.
4. Trace callers of the containing function one level upward.
5. Determine whether the `r0` object or `r1` pointer contains:
   - CM1
   - CM2
   - record 3
   - CCT 2850 / 6807
   - 44-byte record stride
6. Follow the object through:
   - `ca9_cm_set_dng_color_matrix`
   - `ca9_cm_ColorSpec_MapWhiteMatrix`
   - `ca9_cm_ColorSpec_MatrixInterpolate`
7. Determine whether this module only prepares DNG metadata or whether the resulting ColorSpec transform also feeds still JPEG/image formation.
8. Only if live image-formation dataflow is proven should record 3 / the ColorSpec transform be considered for a renderer experiment.

The key fork is:

### If ColorSpec is DNG/metadata-only
Keep COLOR132 out of the renderer and continue searching upstream for the actual JPEG working-space transform.

### If ColorSpec output feeds still image formation
Then replace/refine the provisional `XYZ D50 -> M11 reference basis` bridge with the firmware-derived transform, on a separate experiment branch, preserving RENDER1H.

---

## 16. Android source-adapter caution

Current `M11ReferenceBasisCore` is not firmware-proven at the same level as CC0/CC1/Cat42.

The basis/regression implementation is internally consistent, but its **conceptual placement/working-space identity remains provisional**.

This is the first renderer component that should be challenged if ColorSpec provenance closes.

Do not alter:

- CC0
- CC1
- tone
- gamma
- Cat24
- Cat42

until upstream basis evidence is resolved.

---

## 17. Device-test history relevant to colour issue

Recent same-DNG tests:

- B2RWBPLACE1A: technically valid, orientation regression initially present
- COLORBACK1A: Cat42 off; colour still muted
- COLORRESTORE1A: 1.30× final chroma; colour still muted
- ORIENTFIX1A: orientation corrected successfully

User observation:

> “color is not back ... images look mostly the same just in the right orientation”

Interpretation:

The missing colour is not primarily:

- Cat42 suppression
- modest final-output saturation/chroma
- orientation
- an obvious second B2R WB gain

This is why the current investigation is upstream.

---

## 18. Research scripts/workflows added in this phase

Not exhaustive, but relevant continuation tools include:

- `tools/trace_m11_sro_loader_consumer.py`
- `.github/workflows/r2a-m11-sro-loader-consumer.yml`
- `tools/trace_m11_sro_runtime_slot.py`
- `.github/workflows/r2a-m11-sro-runtime-slot.yml`
- `tools/trace_m11_sro_switch_consumers.py`
- `.github/workflows/r2a-m11-sro-switch-consumers.yml`
- `tools/trace_m11_sro_index5_callers.py`
- `.github/workflows/r2a-m11-sro-index5-callers.yml`
- `tools/trace_m11_resolver_maptype_field.py`
- `.github/workflows/r2a-m11-resolver-maptype-field.yml`
- `tools/scan_m11_resolver_request_maptypes.py`
- `.github/workflows/r2a-m11-resolver-request-maptypes.yml`
- `tools/trace_m11_sro_type5_consumer.py`
- `.github/workflows/r2a-m11-sro-type5-consumer.yml`
- `tools/trace_m11_color132_dng_consumers.py`
- `.github/workflows/r2a-m11-color132-dng-consumers.yml`

Closure report already in repo:

`research/reproduced/M11P_261_SRO_MAPTYPE5_SENSOR_EXCLUSION1A.md`

Note: that report intentionally says the **proven type-5 consumer** is sensor-only while retaining the newer static association between COLOR132 and `sro.bin`.

---

## 19. Important “do not regress” rules

- Keep RENDER1H frozen.
- Keep LibRaw-only orientation.
- Do not add arbitrary saturation.
- Do not remove Cat42.
- Do not add MCC without a real non-identity still-photo payload.
- Do not treat B2R AWB as a second creative-colour stage.
- Do not call COLOR132 record 3 a rendering matrix solely because its values look plausible.
- Do not call COLOR132 DNG-only solely because direct pointer scans are negative.
- Require real producer/consumer dataflow before changing pixel math.

---

## 20. Recommended continuation prompt

Use:

> Continue from `M11_PROJECT_HANDOFF_v1_07_COLOR132_COLORSPEC_PROVENANCE_NEXT_20260915.md`. First trace the `0x016EB088 -> 0x016EB09C` ColorSpec call boundary: decode the PC-relative r1, reconstruct the sp+0x20 object, identify r2=0xDC94, and follow `ca9_cm_set_dng_color_matrix`, `ca9_cm_ColorSpec_MapWhiteMatrix`, and `ca9_cm_ColorSpec_MatrixInterpolate`. Do not mutate RENDER1H until live still-image dataflow proves a replacement/refinement for the provisional M11 reference-basis bridge.
