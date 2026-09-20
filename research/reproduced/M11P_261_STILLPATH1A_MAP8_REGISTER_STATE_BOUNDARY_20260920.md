# M11-P 2.6.1 STILLPATH1A — real still-loader caller, MAP8, MCC state boundary

Date: 2026-09-20. Research only; no renderer or app changes.

## Provenance

Baseline: `c7e0e36d8560c76813ef41be0d257ba13a1c6502` on `work/render1h-cat42yq3a-placement1a`.

Separate research branch: `work/mcc-stillpath1a-20260920`.

Successful probe commit: `bdb0ce19dbd6f558baddd6a4de3cbe4cbd27e789`.

Successful workflow run: `35497043331`; job `106041830831`; artifact `10600996153`, `r2a-m11-stillpath1a`.

Downloaded artifact ZIP SHA-256, verified against GitHub digest:
`b7d670a25cb5b6b218b0a464607086e614ba55e145bc4dc770f0cec10266e264`.

Canonical unpacked firmware SHA-256:
`28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`.

CI checked the full firmware before extraction. Local work checked the artifact ZIP and all seven exported slice hashes/lengths. A separate local verifier resolves four byte-gated relocated jump tables and conditional BX-LR returns; its extended results below are not being represented as the CI probe's own output. That verifier and its results are in the accompanying continuation package.

The workflow initially needed YAML quoting and an explicit shallow-checkout comparison-base fetch. Run `35496785702` completed the trace but failed afterward at git diff; it is not the final successful run. A later output-syntax typo was corrected before the successful run above.

## 1. Correct loader entry — direct caller now established

True entry is `0x01732750`, not the push instruction at `0x01732754`:

```text
01732750  sub sp, sp, #8
01732754  push {fp, lr}
01732758  add fp, sp, #4
```

Exact 12-byte gate: `08d04de200482de904b08de2`.

The preceding function returns at `0x0173274C`; this loader returns at `0x01732A60` and ends exclusively at `0x01732A64`.

The actual caller is `0x017703C8`, instruction bytes `e008ffeb`, BL `0x01732750`. The job starts at `0x0176E75C` and returns at `0x017703D0`; surrounding firmware diagnostics identify `img_macro_if_r2y_init`. The loader diagnostic describes filling an R2Y pipe.

The callback BLX at `0x01770450` belongs to the next callback routine, starting at `0x017703F4`, not to this still-job routine. Do not extend the job's interval to absorb it.

## 2. Still setup connected to the IQ loader

Mode-dependent common-builder calls to `0x0172C19C` occur at `0176E99C`, `0176EC9C`, `0176F200`, `0176F59C`, `0176F828`, and `0176FA78`. The object is built at `fp-0xC4`.

```text
0176FE38 -> 01B2397C Im_R2Y_Stop
0176FE48 -> 01B1B9C8 Im_R2Y_Init
0176FE60 -> 01B1CDA4 Im_R2Y_Ctrl, with fp-0xC4
... output/resize/address controls ...
017703C8 -> 01732750 bulk IQ loader
```

The loader calls these twelve helpers:

```text
01732798 -> 0172CE80 input offset
017327A0 -> 0172CEC8 input gain/clipping
017327E8 -> 0172CF40 CC0
0173282C -> 0172D194 before-tone
01732870 -> 0172D434 tone
017328A8 -> 0172DC88 CC1
017328EC -> 0172E29C gamma-related
01732930 -> 0172DFBC YC/YBlend
01732974 -> 0172E5E8 Y noise reduction
017329B8 -> 0172EC14 edge
017329FC -> 0173148C chroma low-pass
01732A40 -> 0173196C chroma suppress
```

This is control-programming order, NOT a new pixel-stage order.

The CI probe visits the root and 12 helpers, 5,308 unique instruction addresses, with zero unresolved internal transfers. There is no direct call to `01B2D324` (MCC writer) or `01B6B388` (MCC RDMA-address getter) in that bounded graph. External calls remain open boundaries; absence here does not prove global inactivity.

## 3. Parameter map-type 8 selects data, not an MCC API

Thirty local IQ-helper call sites use query `0x0178D0A8`. The CC0 wrapper is a concrete positive example: map-type 8, category 3, query at `0x0172CF90`.

```text
0178D0A8 -> 0178A9AC descriptor diagnostics
         -> 0178C89C data matching
              -> 0178C3D0 map-type selector
```

The PC load at `0178C3D4` is a 19-entry switch guarded by CMP r0,#0x12. For map type 8, word at `0178C3FC` is runtime `41234CAC`; the verified relocation delta gives leaf `0178C4DC`.

The leaf reads `[0x43379A34 + 0x34]`, returns it when nonzero, otherwise reads `[0x43379A34 + 0x38]`:

```text
primary runtime pointer slot:  43379A68
fallback runtime pointer slot: 43379A6C
```

The matcher adds a record offset to the map base at `0178CB70`, writes the selected companion value at `0178CB78`, and returns the data address in r0.

These are IQ-map data pointers, NOT recovered MCC coefficient data. Their runtime values and initialization provenance remain open. Other map types can call external helpers; they are retained as unresolved implementation boundaries.

## 4. Independent local verification

The independent slice verifier resolves these explicitly gated tables:

```text
0172C2C4: common builder, 17 entries
0176E91C: still mode setup, 17 entries
0176FF98: later still mode setup, 17 entries
0178C3D4: parameter map type, 19 entries
```

It checks the instruction, preceding comparison, table targets, alignment and containing routine. Missing firmware bytes cause errors rather than being silently replaced by zeros. A32/Thumb state and conditional BX-LR returns are handled explicitly.

| Static root | Routines | Unique instructions | Internal unresolved transfers | External call targets | Direct MCC calls |
| --- | ---: | ---: | ---: | ---: | ---: |
| Loader plus exported query helpers | 19 | 6200 | 0 | 35 | 0 |
| Shared selector | 4 | 823 | 0 | 3 | 0 |
| Map8 leaf | 1 | 7 | 0 | 0 | 0 |
| Still job plus exported callees | 35 | 11185 | 0 | 51 | 0 |
| Init plus exported callees | 13 | 963 | 0 | 7 | 0 |

Counts are static overapproximations, not device execution counts. Tail branches are also recorded; the selector's external tail is to the logger already present among its call boundaries.

12 decoder tests passed in CI and were repeated locally. 12 additional control-flow/missing-byte tests passed locally. No physical device or full-firmware emulator test was performed.

## 5. Init does not supply a coefficient conclusion

Init reaches reset `01B1833C`, manager init `01B18404`, ring-pixel calculation `01B187B4`, and pipe bounds `01B1AB84`.

At `01B183C8`, reset stores zero to the per-pipe register base selected through runtime pointer array `43201224`; clock-on/off helpers surround it. Firmware assertions identify the clock helpers. The pinned public implementation matches this sequence with a zero write to `F_R2Y.CNTL.CNTL`.

That write and the software-manager RAM clearing do not establish the MCC bank's resulting coefficient state. Reset, retention, identity, bypass and separate initialization remain distinct possibilities requiring evidence.

Likewise, `MCC1BM=0` is not a general MCC-disable bit: its documented bit-shift/saturation-compensation semantics apply when `MCCSL=1`. `MCCSL=0` establishes the known placement, not non-identity activation.

Semantic reference: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`, `MILB_API/Project/ImageMacro/src/imr2y.c` and `imr2y.h`. Public implementation correspondence is not a substitute for Leica byte/value evidence.

## 6. Next gate and freeze

Recover actual MCC register-state provenance: determine coefficient effects of the proven reset/control sequence, trace earlier/alternate writes or genuine RDMA consumers, and trace the map8 pointer-slot producers where useful. Review the finite external-call boundary set instead of treating every unresolved call as a suspected MCC thunk.

Do NOT claim MCC must be missing simply because the hardware implements it; do NOT claim it is inactive solely because this direct call is absent.

Keep the earlier ordinal-table rejection, exact MCC interval `[01B2D324,01B60320)`, and before-tone identity at `01B60320`. RDMA maps remain address-only, not values.

Preserve DIRECTK1A, identity CC0, frozen RENDER1H downstream, inactive Cat25, Cat42 code/512 and hardware-exact=false. No guessed MCC, visual fitting, HDR, exposure/tone compensation or renderer changes. No new APK was produced.
