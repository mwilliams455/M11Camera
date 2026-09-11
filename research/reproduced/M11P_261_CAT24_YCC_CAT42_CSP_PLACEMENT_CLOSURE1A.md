# M11-P 2.6.1 — Category-24 YC / Category-42 CSP placement closure 1A

Date: 2026-09-11
Branch: `work/render1h-cat42yq3a-placement1a`
Scope: placement/domain closure only. No renderer coefficients, strength, Q arithmetic, tone, or colour tuning are changed by this note.

## Conclusion

The Category-24 consumer mapping and the practical Category-24/Category-42 placement question are closed for the Android renderer.

The evidence supports this stage relationship:

`Category-24 matrix -> F_R2Y.YC YC conversion -> established Y/C-domain signal -> Category-42 F_R2Y.CSP chroma suppression`

Therefore the existing RENDER1H ordering is supported:

`CC1 -> recovered YC/YCC conversion -> Cat42 CSP using converted Y -> RGB reconstruction`

Cat42 should use the converted luminance/Y-domain signal, not a separately reconstructed pre-YC RGB-derived Y alternative. No RENDER1I placement experiment is justified from the current evidence. RENDER1H remains frozen.

This conclusion does NOT rely on CPU setter call order or numeric register-address order alone. It combines exact Leica resource-to-consumer dataflow, the pinned hardware register programmers, and the public Milbeaut block semantics.

## Canonical firmware provenance

Official Leica updater:

- expected SHA-256: `0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`

Canonical decompressed M11-P 2.6.1 image:

- size: `97644400` bytes
- SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

All firmware traces below are hash-gated against this exact decompressed image.

## Category-24 resource

Exactly one Category-24 R2YS descriptor is present in the canonical image:

- descriptor index: `7`
- descriptor size: `20`
- map size: `18` bytes
- absolute map offset: `0x002CE238`
- dependencies: none
- map SHA-256: `8378a1f64039be01f3c8a9b761da6dc270d9a458e5fedd8e407f010d1901fd56`

Interpreted as nine signed little-endian 16-bit values, the map is:

`[77, 150, 29, -43, -85, 128, 128, -107, -21]`

or the 3x3 Q8-form matrix:

```text
[[  77,  150,   29],
 [ -43,  -85,  128],
 [ 128, -107,  -21]] / 256
```

## Exact Leica Category-24 -> YC consumer path

The live Leica YC wrapper is at:

- wrapper entry: `0x0172DFC0`
- YC hardware-setter callsite: `0x0172E238`
- YC hardware setter: `0x01B624AC`

The wrapper builds the 18-byte coefficient record in a local buffer. If resource lookup does not return a record, the compiled fallback values are the exact Category-24 values above:

- `0x0172E0C8`: `77`
- `0x0172E0D0`: `150`
- `0x0172E0D8`: `29`
- `0x0172E0E0`: `-43`
- `0x0172E0E8`: `-85`
- `0x0172E0F0`: `128`
- `0x0172E0F8`: `128`
- `0x0172E100`: `-107`
- `0x0172E108`: `-21`

If lookup succeeds, nine signed halfwords are loaded from the returned record at offsets `0x00..0x10` and copied into the same local 18-byte buffer.

Immediately before the hardware-setter call:

```asm
0x0172e224: ...                 ; recover pipe/channel argument
0x0172e22c: sub r3, fp, #0x20  ; address of assembled YC control
0x0172e230: mov r0, r2         ; pipe
0x0172e234: mov r1, r3         ; pointer to YC control / Cat24 coefficients
0x0172e238: bl  #0x01b624ac    ; YC hardware setter
```

This closes the Leica resource-to-consumer mapping: the exact Category-24 18-byte matrix is the coefficient payload passed into the live YC hardware programmer.

The same wrapper performs another resource lookup for selector/category `0x19` (25 decimal) and places small blend-control values adjacent to the coefficient payload before the same setter call. The public live YC ABI contains coefficient and luminance-blend controls, so Category-25 is a strong candidate for that companion blend resource. This Category-25 interpretation is supportive context only and is not required for the Category-24 placement conclusion.

## YC hardware programmer

The exact Leica setter at `0x01B624AC` has the expected Milbeaut ImageMacro hardware traits:

- per-pipe F_R2Y base selection
- `+0x2000` R2Y register-bank addressing
- signed coefficient reads from the control structure
- 9-bit signed field masking/packing
- read/modify/write access to the dedicated YC register footprint

Public/pinned Milbeaut ImageMacro source names this control `R2yCtrlYcc` and the API `im_r2y_ctrl2_yc_convert`. Its live hardware payload is a 3x3 YC conversion matrix plus luminance blend controls.

The public YC footprint is:

- `0x100`
- `0x104`
- `0x108`
- `0x10C`
- `0x110`
- `0x120` (`YBLEND`)

The Leica setter reproduces this footprint and packing behavior. This distinguishes it from ordinary C-structure displacement false positives found by the initial broad scan.

## Category-42 / CSP anchor

Category-42 had already been independently closed to the Milbeaut chroma-suppression hardware path. The combined trace re-identifies the same exact Leica CSP programmer:

- CSP hardware setter: `0x01B68B80`
- sole known direct callsite: `0x01731DB0`
- containing wrapper entry: `0x01731970`

The CSP register footprint is:

`0x580, 0x588, 0x58C, 0x590, 0x594, 0x598, 0x59C, 0x5A0, 0x5A4, 0x5A8, 0x5AC`

The public API is `im_r2y_ctrl3_chroma_suppress`, and its documented operation is color-difference reduction by luminance/chroma reference. This is a Y/C-domain operation, not an alternate RGB-to-Y conversion.

## Placement reasoning

The conclusion rests on three independent layers:

1. **Exact Leica dataflow** — Category-24's exact 18-byte matrix, or an identical compiled fallback, is assembled and passed directly as `r1` to the live YC hardware setter at `0x01B624AC`.
2. **Hardware identity** — that setter programs `F_R2Y.YC` with the public Milbeaut YC-conversion register footprint and signed 9-bit coefficient packing. Category-42 independently programs the later `F_R2Y.CSP` chroma-suppression block.
3. **Block semantics** — YC is the conversion that establishes Y/C quantities; CSP explicitly suppresses chroma by luminance/chroma reference. Thus CSP consumes a signal in the established Y/C domain.

The lower YC register offsets (`~0x100`) versus CSP (`~0x580`) corroborate the topology, but numeric address ordering is not used as standalone proof.

Direct-BL ancestry scanning found no immediate common parent between the two wrappers. That does not weaken the resource/consumer mapping: these wrappers can be reached through dispatch/table mechanisms rather than direct BL calls. Consequently CPU configuration call order remains deliberately outside the proof.

No evidence found in this investigation indicates a mux or alternate Cat42 luminance source that would require Cat42 to derive Y independently from pre-YC RGB.

## Renderer decision

Keep RENDER1H frozen.

Do not introduce a RENDER1I solely to test YC/CSP placement. The current implementation order is supported by the firmware/public-hardware evidence:

```text
CC1
  -> Category-24 YC conversion
       -> converted Y/C-domain quantities
            -> Category-42 CSP using converted Y
                 -> existing RGB reconstruction/output path
```

Any subsequent renderer revision should address a different unresolved firmware behavior and should preserve this placement unless contrary direct data-flow evidence is discovered.

## Reproduction / audit trail

Research tools:

- `tools/trace_m11_cat24_ycc_placement.py` — broad displacement/footprint discovery; useful for discovering the live YC setter but intentionally susceptible to ordinary-structure false positives.
- `tools/trace_m11_cat24_ycc_caller.py` — pinned hash-gated verification of Category-24 resource, YC wrapper, callsite, setter, exact coefficient fallback, `r1` provenance, and CSP anchor comparison.

Workflow:

- `.github/workflows/r2a-m11-cat24-ycc-placement.yml`

Broad discovery + targeted verification run:

- run: `34554402879`
- conclusion: success
- targeted Category-24 trace passed after both firmware hash gates

Fast pinned verification run:

- run: `34554517344`
- head: `010a91472e185ceccb827fdee75215f528bd79e2`
- conclusion: success
- artifact: `r2a-m11-cat24-ycc-placement`
- artifact ID: `10182031332`
- artifact archive digest: `sha256:dc75ddc0a1b2631b25a36b4fedca423ea33ca668aebb560a1e58523df85fd900`

Public Milbeaut source used for ABI/register semantics:

- repository: `ZMlogicL/companyTask`
- pinned commit: `f5fc84bd5c475f4c15017b7bff749f81c3618287`

## Closed vs still open

Closed by this investigation:

- Category-24 exact resource identity and matrix values.
- Category-24 exact Leica consumer wrapper/callsite.
- Category-24 live Milbeaut YC hardware setter.
- Category-24 -> YC conversion hardware mapping.
- Practical YC-before-CSP placement for the renderer.
- Cat42 luminance source choice: use converted Y-domain signal.

Not established by this investigation, and intentionally not claimed:

- exact CPU-time configuration order between every R2Y resource category.
- every possible internal silicon mux state for all camera modes.
- Category-25 companion blend-resource identity as a formal closure.
- any new Cat42 strength/curve/coefficient arithmetic beyond the already frozen RENDER1H behavior.
