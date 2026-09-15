# M11 ColorSpec CC0 quantization — closed

Date: 2026-09-15
Firmware: Leica M11-P 2.6.1
Unpacked SHA256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`
Branch: `work/render1h-cat42yq3a-placement1a`

## Status

The floating 3x3 ColorSpec matrix -> 44-byte CC0 hardware record encoding boundary is closed.

## Record layout

`0x016F1CB8` materializes 44 bytes / 11 signed 32-bit words:

- `+0x00..+0x20`: nine matrix coefficients, row-major
- `+0x24`: shift `s`
- `+0x28`: auxiliary scalar

The still R2Y bridge consumes the nine coefficients and the low byte of the `+0x24` shift/control field.

## Shift selection

`0x016F1FB4` chooses the smallest `s` in `{0,1,2,3}` for which the rounded scaled matrix fits signed 12-bit coefficients.

For candidate shift `s`:

`scale = 2^(9-s)`

It computes:

- matrix maximum via `0x016EDFE4`, reducing the nine doubles with `0x016F1700` = floating max
- matrix minimum via `0x016EE13C`, reducing the nine doubles with `0x016F1780` = floating min

The candidate is accepted when:

`round(min(M) * scale) >= -2048`

and

`round(max(M) * scale) <= 2047`

The first fitting candidate is retained.

## Coefficient encoding

For each floating coefficient `M[i]`:

`q[i] = clamp(-2048, round(M[i] * 2^(9-s)), 2047)`

where:

- `round` is the Thumb routine at `0x01C4BAC0`
- `clamp` is `0x016F1844`

`0x016F1844` is exactly the composition of integer min/max helpers:

`max(lower, min(value, upper))`

with `lower=-2048`, `upper=2047` for CC0 coefficients.

## Rounding semantics

`0x01C4BAC0` is entered through A32 `BLX` and is Thumb code. Its bit-level IEEE-754 implementation matches C99 `round()` semantics for double precision:

- nearest integer
- exact half ties away from zero
- `|x| < 0.5` -> signed zero
- `0.5 <= |x| < 1` -> `+/-1`
- already integral / sufficiently large finite values pass through
- NaN/Inf follow the routine's propagation branch

Therefore this is **not** ties-to-even / banker's rounding.

## Auxiliary scalar

The fourth input register to `0x016F1CB8` is converted to double, passed through the same rounding routine, converted back to signed integer and stored at record `+0x28`. It is separate from the hardware shift at `+0x24`.

## Parity formula

For the nine hardware coefficients, the desktop implementation can now reproduce Leica's quantizer as:

```text
for s in 0..3:
    scale = 2^(9-s)
    if round_away(min(M) * scale) >= -2048 and
       round_away(max(M) * scale) <= 2047:
        break

for i in 0..8:
    q[i] = clamp(round_away(M[i] * scale), -2048, 2047)
```

with `round_away` equivalent to C99 `round()` on finite doubles.

## Consequence

The CC0 quantization/encoding boundary no longer blocks a desktop parity implementation. The remaining substantive task is upstream: reproduce the floating 3x3 matrix that ColorSpec feeds into this encoder.

`RENDER1H` remains frozen until that floating matrix composition is closed and tested against firmware-derived records.
