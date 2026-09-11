# M11-P Category 24 / 25 YC consumer — closed

Date: 2026-09-11

Firmware gate:

- LEICA_M11-P_2.6.1.FW SHA-256 `0618ccb180cf3aa8979b04c0851e127753cd6aff3aaffee737abc52388363b83`
- unpacked image SHA-256 `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Closed chain

Leica wrapper `0x0172DFC0` builds the YC control structure and calls low-level setter `0x01B624AC` at callsite `0x0172E238`.

### Category 24 (`0x18`)

The wrapper queries category 24 through `0x0178D0A8` and copies nine signed 16-bit values from offsets `0x00..0x10` into a contiguous 18-byte matrix payload.

If category 24 is absent, the wrapper writes this exact fallback matrix:

```
  77  150   29
 -43  -85  128
 128 -107  -21
```

This is the already-extracted Category-24 payload and matches the public Milbeaut sample YC conversion matrix exactly.

### Category 25 (`0x19`)

The same wrapper then queries category 25 through `0x0178D0A8`. It reads two values, truncates them to the low 8 bits, and stores them immediately after the 18-byte matrix at control-structure offsets `0x12` and `0x13`.

If category 25 is absent, both values are explicitly set to zero.

### Low-level hardware consumer `0x01B624AC`

The setter consumes the combined structure:

- matrix values at `+0x00,+0x02,...,+0x10` are sign-normalised to 9 bits;
- they are packed into R2Y YC registers `+0x100,+0x104,+0x108,+0x10C,+0x110`;
- blend byte at `+0x12` is masked to 6 bits and written into YBLEND bits `0..5`;
- blend byte at `+0x13` is masked to 6 bits and written into YBLEND bits `8..13` at register `+0x120`.

Direct-call scan finds one caller of the setter: `0x0172E238`, inside wrapper `0x0172DFC0`.

## Independent calibration

The contextual same-base register scanner was calibrated against the already-closed Category-42 CSP programmer. It rediscovered:

- CSP setter `0x01B68B80`;
- sole direct caller/callsite `0x01731DB0`.

Only after that calibration passed was the Category-24 YC candidate accepted.

## Public Milbeaut corroboration

Pinned public source: `ZMlogicL/companyTask@f5fc84bd5c475f4c15017b7bff749f81c3618287`.

`R2yCtrlYcc` is laid out as nine signed 16-bit `ycCoeff[3][3]` entries plus Y and Yb blend controls. The sample configuration uses the identical nine matrix values and sets both blend ratios to zero. The public hardware register family is YC `+0x100..+0x110` plus YBLEND `+0x120`.

## Conclusion

Category 24 is conclusively the Leica M11-P YC 3x3 conversion matrix. Category 25 supplies the two YC blend controls. Together they feed the Leica YC hardware consumer at `0x01B624AC`.

This closes the Category-24 consumer question. It does **not** by itself establish silicon pixel-stage order relative to Category-42/CSP. CPU configuration-call order and register-address order remain insufficient as sole evidence for pixel ordering.

## Derived probes

- `tools/match_milbeaut_ycc_fingerprint.py`
- `tools/trace_m11_cat24_ycc_register_footprint.py`
- `tools/trace_m11_cat24_ycc_contextual.py`
- `tools/trace_m11_cat24_ycc_focus.py`
- workflows `r2a-m11-cat24-ycc-*`
