# M11-P 2.6.1 — 600-byte R2YS family / Category-27 edge exclusion 1A

Date: 2026-09-11
Branch: `work/render1h-cat42yq3a-placement1a`
Scope: resource identity / MCC exclusion only. No renderer change.

## Conclusion

The 600-byte R2YS resource family is **not** the missing MultiAxis/MCC MCK+MCL payload.

The apparently attractive geometry (`600 = 4 * 150` bytes, and `3 * 600 = 1800` bytes) is accidental with respect to MCC. Exact Leica request-field evidence ties the family to the already-identified Category-27 edge/sharpness wrapper at `0x0172EC18`.

## Why the size hypothesis looked plausible

The closed public `CtrlMultiAxis` logical layout contains 12 colour areas. Per area, the MCK and MCL logical coefficient arrays occupy 90 + 60 = 150 bytes, so four logical areas occupy 600 bytes and all 12 occupy 1800 bytes.

The M11-P R2YS database contains many 600-byte map descriptors, including long sequences of three 600-byte entries. Size alone therefore looked like a possible segmented MCC representation.

## Exact selector evidence

The live Leica wrapper `0x0172EC18..0x0173148C` is already closed to the Category-27 edge/sharpness family. Before its R2YS resolver call at `0x0172F0FC`, it constructs the request object at `fp-0x224`:

- request `+0`: `8`
- request `+4`: caller selector, accepted only when it is `0x10` or `0x11`
- request `+8`: `0x1B` = decimal 27
- additional request fields carry ISO/exposure/state dimensions

Relevant instructions:

```asm
0x0172ef34: cmp r3, #0x10
0x0172ef40: cmp r3, #0x11
...
0x0172f0c0: mov r3, #8
0x0172f0c4: str r3, [fp, #-0x224]
0x0172f0c8: mov r3, #0x1b
0x0172f0cc: str r3, [fp, #-0x21c]   ; request +8
0x0172f0d0: ldr r3, [fp, #4]
0x0172f0d4: str r3, [fp, #-0x220]   ; request +4
...
0x0172f0fc: bl  #0x0178d0a8        ; R2YS resolver
```

The 600-byte descriptor family matches those request dimensions exactly:

- the descriptor field historically labelled `category` is predominantly `16` or `17`, matching request `+4`;
- dependency slot 0 is consistently `27`, matching request `+8` / the proven Category-27 selector;
- the remaining dependency slots encode the same ISO/exposure/creative-state dimensions used by this wrapper;
- repeated descriptors often alias the same 600-byte map under different dependency ranges/states.

This explains why an earlier simplistic `by_category[27]` lookup found no literal fixed-field Category-27 descriptors: for this extended descriptor family, the semantic selector 27 is represented in dependency slot 0 while another request dimension occupies the fixed field parsed as `category`.

## Payload character

The 600-byte maps are sparse/control-like rather than photographic MCC coefficient surfaces. A representative map has 300 signed 16-bit words with 261 zeros and only ten unique values; common non-zero values include `16`, `58`, `128`, `256`, `511`, `1023`, and `-64`.

More importantly, the resource-to-consumer path already identifies the Category-27 family as edge/sharpness configuration. Its low-level consumers were independently named as HighEdge Scale/Step, MediumEdge Scale/Step, LowEdge Scale/Step and MapScl controls.

## Renderer decision

Do not add these 600-byte resources to RENDER1H as MultiAxis/MCC colour data.

RENDER1H remains frozen. The MCC search must use consumer/dataflow evidence, not size coincidences.

## Parser note

`parse_r2y()` currently exposes the fixed descriptor field as `category`. That name remains useful for the simple primary families already reproduced (e.g. Categories 3, 13, 24, 42), but this investigation proves it is not universally equivalent to the semantic R2YS request category for extended flag layouts such as `0x80f`.

Do not globally rename or reinterpret existing reproduced assets without a separate descriptor-ABI investigation; instead, treat the request-field mapping as flag/layout-dependent.

## Reproduction

Probe:
- `tools/trace_m11_mcc_600_resource_family.py`
- `.github/workflows/r2a-m11-mcc-600-resource-family.yml`

Successful run:
- Actions run `34573476603`
- head `939e8f1d850d21215295519546651877cf73b3ba`
- artifact `r2a-m11-mcc-600-resource-family`
- artifact ID `10188688339`
- artifact digest `sha256:9ab02d6e7e0d9985b98a1c5c191fb6f31adb9a6202138b16978ffc122f20fe00`
