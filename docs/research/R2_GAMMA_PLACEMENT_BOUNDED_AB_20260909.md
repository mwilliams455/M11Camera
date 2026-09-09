# R2 bounded gamma-placement decision — 2026-09-09

## Scope

This note closes the current expensive static-investigation branch around Leica M11/M11-P Category 15/20 gamma placement.

No canonical renderer behavior is changed by this result.

## Inputs held fixed

- exact hash-gated Leica M11-P 2.6.1 updater;
- exact recovered Category 15/20 high-nibble-first gamma curve;
- exact Standard Category-6 tone-gain table;
- recovered CC0 and low-ISO CC1 matrices;
- H1 DNG scene-PCS -> Standard-A WB camera-basis bridge;
- the same 12 matched original Leica M11 DNG/JPEG pairs used by the prior hue-vs-luma probe;
- ICC-managed JPEG decoding to linear sRGB;
- common alignment and common comparison mask;
- Leica Category-24 YC chroma-hue residual as the A/B metric.

No exposure, matrix, gamma, tone, per-scene or chroma parameter was fitted.

## Compared placements

### A — current provisional renderer placement

`CC0 -> Standard tone -> CC1 -> YC -> Cat15/20 gamma(Y) -> inverse YC`

### B — public-Milbeaut hardware-order candidate

`CC0 -> Standard tone -> Cat15/20 gamma(RGB-common component-wise) -> CC1`

The still-open exact Category-42 chroma-suppress stage was excluded because symmetric chroma magnitude is not required for the hue-direction comparison.

## Result

All 12 pairs aligned successfully.

- A wins: **9**
- B wins: **3**
- ties: **0**
- paired two-sided sign-test p: **0.14599609375**
- median pair median absolute hue error, A: **2.8116369247 degrees**
- median pair median absolute hue error, B: **3.1886702776 degrees**

Per-pair winners:

| Pair | ISO | A hue error | B hue error | Winner |
| --- | ---: | ---: | ---: | --- |
| 01 | 125 | 3.4165 | 3.1145 | B |
| 04 | 64 | 2.6502 | 3.4145 | A |
| 05 | 1250 | 4.4897 | 4.2524 | B |
| 10 | 64 | 1.2063 | 1.3765 | A |
| 14 | 64 | 1.9345 | 2.1282 | A |
| 20 | 80 | 1.8663 | 2.8839 | A |
| 24 | 64 | 0.9762 | 3.7184 | A |
| 31 | 125 | 3.6045 | 4.0132 | A |
| 34 | 640 | 2.8940 | 4.4083 | A |
| 37 | 800 | 2.8400 | 2.5304 | B |
| 38 | 1600 | 2.8827 | 3.0983 | A |
| 45 | 100 | 2.7833 | 3.2628 | A |

## Interpretation

The photographic A/B leans toward placement A, but the result is **not statistically strong enough to promote A as proven Leica runtime behavior** under the predeclared paired decision rule.

It does, however, provide no empirical reason to replace the current provisional Y-after-YC renderer with the tested RGB-common-before-CC1 implementation.

The earlier hue-vs-luma diagnostic is also not used as placement proof because its intended positive control failed directionally: H1 code/linear slope ratio was ~0.794 rather than >1.

## Static-loader research closure

The following static routes were exhausted without a credible Category-15/20 runtime bridge:

- direct raw/virtual Cat15/Cat20 map-address xrefs;
- MOVW/MOVT map-address constructions;
- direct B/BL/BLX callers of the proven R2YS validator;
- raw or translated validator pointer words;
- ADR-style validator constructions;
- raw/translated MOVW/MOVT validator constructions;
- register-only descriptor geometry scan;
- saved-pointer-origin descriptor selector scan.

The origin-aware selector scan still found generic structures with +4/+8/+0xc/+0x10 fields, but **zero verified descriptor-size iterator and zero direct Cat15/20 compare**. Those candidates are not promoted.

## Decision

1. **Keep canonical renderer frozen.**
2. **Keep placement A as provisional only.**
3. **Do not continue broad static R2YS loader/category archaeology.**
4. Reopen Cat15/20 placement only if new high-value evidence appears, preferably:
   - direct runtime request/object-ID capture;
   - direct consumer trace from the opposite side of the BB060014 receive boundary;
   - hardware/register trace showing Leica's actual gamma table slot/mode; or
   - a stronger matched-corpus experiment with a newly justified discriminator, not another variant of the searches already closed.
5. Shift project effort to the controlled renderer / device-validation path rather than spending additional cycles on this unresolved static linkage.

## Reproducibility

Workflow run: `34320312528`

Workflow: `.github/workflows/r2-m11-gamma-placement-ab.yml`

Probe: `tools/probe_m11_gamma_placement_ab.py`

Source commit for the successful run: `ee1ac9d0f2b39174c2f30dbda35e41f9ab599504`
