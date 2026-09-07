# Leica M11 Project Handoff v0.1

**Date:** 2026-09-07  
**Target device:** Xiaomi 15 Ultra  
**Reference target:** Leica M11 / M11-P processing  
**Initial firmware reference:** Leica M11-P 2.6.1  

## Project direction

This project is no longer a LUT-emulation project. The old Xiaomi+DCP+3D-LUT work is retained only as visual/regression reference material.

The target architecture is:

```text
Xiaomi 15 Ultra RAW
→ per-physical-camera Xiaomi source adapter
→ common scene-referred colour representation
→ M11 input-space bridge
→ firmware-derived Leica M11 processing core
→ output transform
→ full-resolution sRGB JPEG
```

Start with **Xiaomi main camera + M11 Standard + single-frame RAW**. Natural/Vivid, additional lenses and capture-policy emulation come later.

## Existing M11 work to preserve

The saved M11 research already contains a firmware-derived reference model rather than only hand-tuned LUTs. Current recovered/working components include:

- candidate CC0 and CC1 signed 3×3 matrices, currently modeled as Q9 / 512;
- reconstructed 1024-point Q12 tone family with contrast positions -3…+3;
- Leica Y/Cb/Cr-like integer transform;
- reconstructed 4096-step gamma table;
- Natural / Standard / Vivid contrast and chroma states;
- a Python M11 reference renderer and firmware extraction tooling.

Current investigation model:

```text
scene-linear M11 working RGB
→ CC0
→ Leica luminance/tone stage
→ CC1
→ Leica Y/Cb/Cr-like basis
→ gamma candidate
→ mode-dependent chroma
→ inverse Y/Cb/Cr
→ output
```

This order is a working model, not permission to call every edge firmware-proven.

## Important open questions

1. Exact physical/semantic colour domain entering CC0.
2. Exact semantic destination of CC1.
3. Exact CC0/tone/CC1 ordering in the still path.
4. Gamma-table placement and precision.
5. Whether a separate final output OETF follows the recovered gamma stage.
6. Clip/headroom locations and integer rounding semantics.
7. Output-gamut handling.
8. ISO-dependent behaviour.
9. Whether Leica still rendering uses any additional local tone, sharpening, texture or noise-dependent chroma protection stages relevant to this port.

## Xiaomi source side

Reuse the independent Xiaomi source-characterization architecture developed during the M9 work. The source adapter must remain separable from the Leica target renderer.

Preferred shared handoff space:

```text
linear XYZ D50
```

Do not treat a DNG `ColorMatrix` like a `ForwardMatrix`; preserve correct DNG semantics when reconstructing sensor→XYZ behaviour. Lens-shading/GainMap correction is geometric/radiometric source normalization, not creative Leica colour processing.

## Old LUT work

Keep accepted M11 LUTs as visual controls only. Do not make them architectural dependencies.

Do not carry forward as Leica truth:

- FleeceGuard;
- fake microcontrast encoded into 3D LUTs;
- Adobe Curve as the permanent Leica tone engine;
- a fixed 4080 K bridge;
- Cobalt as a required source dependency.

## Milestones

### R0 — Evidence + Input-Space Bridge

- reproduce existing firmware-derived assets;
- inventory provenance/hashes;
- parse genuine M11/M11-P DNG metadata;
- define the colour domain feeding CC0;
- establish a defensible XYZ D50 → M11 working/input RGB bridge;
- keep Standard deterministic and scene-independent.

### R1 — Genuine-Pair Stage-Order Validation

Use genuine M11/M11-P DNG+JPEG pairs to test stage toggles and close:

- CC0/tone/CC1 order;
- gamma placement;
- output transfer;
- clipping/headroom;
- fixed-point/rounding behaviour where recoverable.

### R2 — Xiaomi Main Native Source Adapter + M11 Standard

Feed Xiaomi 15 Ultra main-camera RAW through the independent source adapter and then the now-validated M11 core. No LUT dependency.

### R3 — Android Main/Standard Single-RAW Port

Preferred runtime:

```text
Camera2 RAW_SENSOR Image
→ native libm11render
→ full-resolution M11 JPEG
```

During development, the same RAW may also be sent to Android `DngCreator` for an archival/debug DNG.

### R4/R5 — Modes, lenses and later capture-policy work

Only after main/Standard parity is strong:

- Natural;
- Vivid;
- ISO-dependent behaviour;
- ultrawide;
- tele;
- super-tele;
- separate investigation of Leica M11 metering/exposure behaviour if desired.

## Non-goals for the first renderer

Do not add phone-style HDR fusion, Ultra HDR JPEG, AI scene classification, face rendering, arbitrary highlight guards, automatic shadow lifting, creative LUTs, synthetic Leica grain, fake microcontrast or M9 exposure constants to compensate for an uncertain M11 model.

## First decisive work item

The highest-value next result is:

```text
validated M11 input-space bridge
+
genuine M11 Standard DNG/JPEG regression corpus
```

The project should be treated as a renderer-porting effort, with firmware evidence kept distinct from visual approximation.
