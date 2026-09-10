# M11-P Category 42 transfer geometry — Q3/Q9 HYPOTHESIS1A

**Date:** 2026-09-10  
**Firmware:** Leica M11-P 2.6.1  
**Evidence branch:** `research/m11-cat42-consumer1a`

## Scope

This note extends the already-proven Category 42 -> Milbeaut `CsCo` / Chroma Suppress register mapping. It does **not** claim the hardware pixel equation is closed. The purpose is to record a strong fixed-point pattern in the seven creative saturation maps and define a bounded next test without turning a visual guess into firmware truth.

## Exact creative-state family

```text
state   offsets[0..3]       gains[0..3]      borders[0..2]
-3      258 357 357 332     26 0 -4 -19      31 946 992
-2      258 434 434 389     26 0 -4 -19      54 888 969
-1      258 511 511 447     26 0 -4 -20      77 831 946
 0      258 588 588 505     26 0 -4 -20     100 771 922
+1      258 665 665 563     26 0 -4 -20     124 713 899
+2      258 741 741 620     26 0 -4 -20     147 656 876
+3      258 818 818 677     26 0 -4 -20     170 598 853
```

## Q9-like offset family

The middle two offsets are equal in every creative state:

```text
357, 434, 511, 588, 665, 741, 818
```

Normalising by 512 gives:

```text
0.6973, 0.8477, 0.9980, 1.1484, 1.2988, 1.4473, 1.5977
```

The state-to-state increment is approximately 77 codes, i.e. `77 / 512 = 0.15039`. State `-1` is essentially unity (`511 / 512 = 0.99805`), while Standard state `0` is `588 / 512 = 1.14844`.

This does **not** resurrect the disproven global `Cb/Cr *= 1.15` interpretation. It instead suggests that the four `CSYOF` values may encode a local chroma-retention/scale transfer in a Q9-like domain.

## Strong Q3-like gain geometry

Treating the signed `CSYGA` values provisionally as slopes with three fractional bits produces a striking near-continuity pattern.

### Low-side segment

Candidate relation:

```text
next ~= offset0 + gain0 * border0 / 8
```

Residuals in codes for states -3..+3:

```text
-1.75, +0.50, +2.75, +5.00, +4.00, +5.25, +7.50
```

With `offset0 = 258` and `gain0 = +26`, the effective slope is approximately `26/8 = +3.25` codes per reference step.

### High-side segment

Candidate endpoint relation:

```text
endpoint ~= offset3 + gain3 * (1023 - border2) / 8
```

The predicted endpoint remains close to the same fixed code `258` for every state. Residuals versus 258 are:

```text
-0.375, -2.75, +3.50, +5.50, +5.00, +5.50, +6.00
```

This is strong evidence that the 10-bit reference domain is bounded around `0..1023` and that the gain field has approximately Q3 slope semantics.

### Middle falling segment

Using the same simple segment-local Q3 equation for `gain2 = -4` predicts `offset3` less accurately; residuals grow from -2 to -13.5 codes across the creative states. Therefore the exact transfer equation, internal rounding, segment anchoring, or reference coordinate is still unresolved and must not be claimed from this pattern alone.

## Photographic interpretation consistent with the registers

If the offsets are a Q9-like chroma-retention quantity and the reference coordinate is luminance-dominant, Standard state 0 would have an approximate shape:

```text
reference 0            -> ~258/512 = 0.50
rises toward border 100 -> ~588/512 = 1.15
broad middle region     -> ~1.15
falls after border 771
near border 922         -> ~505/512 = 0.99
reference 1023          -> ~0.50
```

That shape would suppress chroma in deep shadows and extreme highlights while allowing stronger colour through most midtones. It also explains why the historical global 1.15 multiplier moved the renderer in the right direction but over-saturated skin and other already-strong colours.

This remains a **hypothesis**, not a firmware claim.

## CSYKY=8 input-coordinate clue

The public Milbeaut field name is `CSYKY`, documented as the luminance/chroma mixing ratio with range 0..8. Leica uses value 8 for all seven creative states. The `YRV` control can separately reverse the 10-bit luminance coordinate as `1023-Y`, while `CRV` separately reverses chroma data.

The naming and endpoint value make a pure- or maximally-Y-weighted reference at `CSYKY=8` plausible, but the exact mixing equation and which endpoint corresponds to pure Y are not yet proven.

## RENDER1E device evidence

Two new Xiaomi 15 Ultra device renders were inspected after removal of the provisional global 1.15 chroma multiplier:

- ISO 50 flower scene: the RGB-common gamma path remains visually stable and preserves strong pink/green separation without the prior global chroma push.
- ISO 347 portrait scene: skin remains warm but is materially less globally over-driven than the prior 1.15 candidate; highlight behaviour is stable.
- The RENDER1E diagnostic path has no downstream chroma change at the candidate YCC stage (`before == after` by construction), so these samples are a clean neutral-chroma control for the next Category-42 test.

## Next bounded experiment

Do **not** alter gamma placement, CC1, tone, source calibration, or output encoding.

Build a diagnostic `CAT42Y1A` candidate only if it is clearly labelled as provisional:

1. preserve RENDER1E as the control;
2. use the Standard Category-42 map `[258,588,588,505] / [26,0,-4,-20] / [100,771,922]`;
3. evaluate a 10-bit candidate reference from the current post-CC1 Y component;
4. evaluate the four-region transfer with Q3 gain (`/8`) and Q9-like scale (`/512`);
5. multiply Cb and Cr by the resulting local scale;
6. record scale/reference histograms and clamp statistics;
7. do not promote this equation as Leica-exact until the CSYKY endpoint and middle-segment arithmetic are independently closed.

A second counterfactual using chroma magnitude as the reference can be retained offline or diagnostically to distinguish Y-reference from C-reference without changing any other stage.
