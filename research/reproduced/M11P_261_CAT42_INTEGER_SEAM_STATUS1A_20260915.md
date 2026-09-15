# M11-P 2.6.1 — Cat42 integer seam STATUS1A

Date: 2026-09-15

## Purpose

This note records the exact state of the remaining Category42 / R2Y chroma-suppress arithmetic seam after DIRECTK1A was promoted for Xiaomi cross-camera entry. It deliberately separates **closed M11 renderer facts** from **silicon details that are still not proven**. No photographic tuning is introduced here.

## Frozen upstream/downstream context

The current Xiaomi path remains:

`Xiaomi camera RGB -> Xiaomi dual-illuminant characterization + live neutral WB -> XYZ D50 -> firmware PCS_TO_INTERNAL K -> identity CC0 -> frozen RENDER1H tone / CC1 / gamma / Cat42 / orientation / output`

DIRECTK1A is closed by four same-DNG device A/B scenes and is not part of this investigation.

## Category42 hardware identity — closed

Public Milbeaut R2Y driver/API source independently identifies the block programmed by the recovered Leica Category42 values as the **R2Y chroma suppress (CSP)** block. The driver writes:

- `CSYCTL.CSYKY`
- `CSYOF_0..3`
- `CSYGA_0..3`
- `CSYBD_1..3`

The public API documents:

- `CSYKY`: 4-bit mixing ratio, valid 0..8
- `CSYOF`: four 10-bit offsets
- `CSYGA`: four 11-bit signed gains
- `CSYBD`: three 10-bit borders

This independently matches the Leica firmware Category42 structure already recovered in this repository. The driver is a register-programming implementation; it does not expose the hidden per-pixel comparator or signed multiply/shift equation inside the silicon.

## M11 reference axis — closed

For the creative Category42 family, Leica fixes `CSYKY = 8`. The separate endpoint-semantics proof closes the M11 reference coordinate to the post-CC1 luminance/Y endpoint used by the current candidate. This seam is not reopened here.

## Gain generator — closed

The recovered Category42 table generator reproduces all 28 creative gain codes and establishes the stored gain representation as signed Q3 slope codes for the Leica family.

## Output scale-code encoding — CLOSED at engineering threshold

`tools/analyze_m11_cat42_scale_encoding.py` establishes the M11 renderer interpretation:

**`CSY scale = stored_code / 512.0`**

with no register `+1` term.

Evidence:

1. Category42 is the only saturation-selected R2YS family in the recovered Leica configuration.
2. Its active +10 monochrome state keeps CSP enabled (`EN=1`, `KY=8`, `TBL=0`) but programs all four offsets and gains to zero.
3. Q9 (`/512`) is the only nearby power-of-two denominator whose creative -3..+3 plateau codes straddle unity.
4. Direct `/512` preserves the deliberate stored zero as exact zero.
5. `(code+1)/512` would require an otherwise-unseen zero special case to make the active monochrome map actually zero.

Therefore the old checklist item “register +1 scale-code semantics” is no longer an open renderer decision. The promoted M11 interpretation is direct, zero-preserving Q9.

This is an engineering closure for the recovered Leica M11 configuration, not a claim to possess undocumented Socionext vendor RTL.

## Remaining hidden-silicon ambiguity — bounded, not falsely closed

The remaining uncertainty is now limited to the silicon's exact piecewise evaluation at 10-bit reference coordinates:

1. border ownership/equality (`<` versus `<=` at each `CSYBD` handoff),
2. signed negative Q3 division/shift rule,
3. exact reference-code quantization immediately before CSP if the hardware receives more than the exposed 10-bit coordinate.

The existing Y-closed sweep (`R2A M11 Cat42 rounding boundary sweep`, run `34513211983`) enumerates 48 plausible variants. With the structurally preferred local coordinate `x - segment_start`, the maximum envelope across border mode × signed rounding × clamp is:

| creative state | max scale-code span | mean span | affected Y codes |
|---:|---:|---:|---:|
| -3 | 2 | 0.068359 | 68 / 1024 |
| -2 | 5 | 0.117188 | 116 / 1024 |
| -1 | 7 | 0.140625 | 136 / 1024 |
| 0 | 8 | 0.184570 | 178 / 1024 |
| +1 | 9 | 0.224609 | 219 / 1024 |
| +2 | 11 | 0.267578 | 259 / 1024 |
| +3 | 14 | 0.310547 | 298 / 1024 |

For the same right-open/local-start geometry, changing only the signed rounding rule from arithmetic shift to the closest alternatives changes scale by at most **one code** (`1/512 = 0.001953125`) and affects only a subset of the 10-bit Y domain:

- nearest-away: 381 / 7168 state×code samples (5.315%)
- nearest-even: 718 / 7168 (10.017%)
- toward-zero: 912 / 7168 (12.723%)

The larger 14-code envelope is driven by combinations of border ownership and negative-slope handoff behavior, not a global scale uncertainty.

## Current renderer candidate

Until primary silicon documentation or a hardware-output oracle distinguishes the hidden comparator/shift convention, the renderer retains the existing candidate:

- reference: post-CC1 Y, bounded/quantized to 10-bit
- four-segment local coordinate: `x - segment_start`
- border convention: right-open / bounded
- signed Q3 division: arithmetic-shift-equivalent floor for negative values
- output scale decoding: **direct code / 512**

The metadata flag `category42IntegerConventionHardwareExact=false` must remain false. This is intentional: the M11 photographic renderer can use the best-supported convention without claiming an undocumented silicon detail has been recovered.

## Why this should not block the next M11 work

The dominant Category42 structure is already closed: hardware block identity, register geometry, Y endpoint, Leica table generator, Q3 gain codes, segment data and direct Q9 scale decoding. The residual integer ambiguity is localized to boundary/rounding behavior and is quantitatively bounded.

Accordingly:

- do **not** tune photographs to choose among these hidden-silicon variants;
- do **not** alter DIRECTK1A, tone, CC1, gamma placement, Cat42 placement, WB, or output math to compensate for it;
- keep the exact-hardware flag false;
- move the main firmware investigation forward, while preserving a synthetic `border-1 / border / border+1` regression probe for any future silicon evidence.

## Next engineering action

Add a deterministic Cat42 boundary oracle test covering, for every creative state and each of the three borders:

- `border-1`, `border`, `border+1`
- positive, zero and negative gain segments
- Y=0 and Y=1023
- direct `/512` output decoding
- explicit arithmetic-shift candidate output

This should lock the present candidate against accidental implementation drift without presenting it as hardware-exact. If later primary evidence identifies comparator ownership or signed shift semantics, only that isolated oracle and CSP evaluator should change.