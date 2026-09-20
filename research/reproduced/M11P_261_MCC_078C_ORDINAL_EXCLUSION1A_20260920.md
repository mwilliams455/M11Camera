# M11-P 2.6.1 — MCC 0x78C ordinal exclusion 1A

Date: 2026-09-20
Canonical unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Closure

The isolated-size interpretation of the aligned word `0x0000078C` at file offset `0x0322DB4C` is rejected. It occupies the ordinal field of a fixed-stride record sequence. Its equality to the proposed `CtrlMultiAxis` size is a numeric coincidence, not MCC provenance.

This does NOT establish the subsystem owning the record table. It does NOT establish whether MCC is inactive. It removes this particular object-size lead.

## Original artifact re-examination

Run `34975721840`, artifact `10399082445`, name `r2a-m11-mcc-078c-xrefs`:

- ZIP SHA-256: `6e5798f5a757eafe9fcb6d32d5f3e3d89de4d44c240ca95dc336217ea7cf45cb`
- extracted `mcc_078c_xrefs.md` SHA-256: `01535a20533d996e4668ce961d42d5f105018a26c31cdb42d1db1e4406b1819e`

Its wider-neighborhood dump already contains 43 consecutive ordinal fields, from `0x777` through `0x7A1`, separated by exactly `0xBC` (188) bytes. This was more informative than the report's zero-xref counts.

Immediate witness:

| File offset | Value |
| --- | --- |
| `0x0322D918` | `0x789` |
| `0x0322D9D4` | `0x78A` |
| `0x0322DA90` | `0x78B` |
| `0x0322DB4C` | `0x78C` |
| `0x0322DC08` | `0x78D` |
| `0x0322DCC4` | `0x78E` |
| `0x0322DD80` | `0x78F` |

## Canonical-firmware reproduction

Probe: `tools/trace_m11_mcc_entryaudit1a.py`
Successful analysis run: `35495270420`
Run commit: `9ffca110e53458a8184f1f1f1b7562978c2cf88b`
Artifact: `10600398488`, ZIP SHA-256 `6f7db83992a99621f7013550b6e0190e97b56ca3b2a6ebfaa99fbcd8d450cf4b`

The hash-gated full-image scan expands the witness to:

- first ordinal field: `0x031D507C`, value `0`
- last ordinal field: `0x0323D674`, value `2274` (`0x8E2`)
- count: **2275**
- field stride: **188 bytes / 0xBC**

For every n from 0 through 2274, inclusive:

`u32_le(image, 0x031D507C + n * 0xBC) == n`

In particular:

`0x031D507C + 0x78C * 0xBC == 0x0322DB4C`

The sequence alone explains the unique aligned `0x78C` occurrence. Do not pursue this word as an allocation length or infer an MCC object from a referenced owner of this table.

## Independent writer-entry audit

The entry audit independently confirms the previously identified API boundary:

- `0x01B2D320`: preceding function's `pop {fp, pc}`
- `0x01B2D324`: MCC `push {fp, lr}`
- `0x01B2D328`: `add fp, sp, #4`
- subsequent code saves the control pointer, checks NULL / pipe range, and begins MCC register programming.

Thus the zero exact-entry caller result is NOT explained by an entry address a few instructions too late.

Precise end-boundary clarification:

- MCC return instruction is at `0x01B6031C`.
- `0x01B60320` is the exclusive end and the NEXT function's prologue, not the return instruction itself.
- The full function byte extent remains `[0x01B2D324, 0x01B60320)`, length `0x32FFC` / 208892 bytes.
- The raw call `0x0172D3B0 -> 0x01B60320` therefore targets the next function and must not be reported as an MCC invocation.

No exact-entry A32 B/BL candidate was found. The scan also recovers the established direct still-dispatch targets at `0x0176FE38..0x0176FF88`, providing positive controls. Raw candidates elsewhere in the image are not promoted without executable-code/CFG validation.

## Live-path question remains open

A driver routine's presence, its complete hardware geometry, and `MCCSL=0` establish availability and selected architectural placement. They do not alone prove that the still path programs a non-identity MCC transform.

Continue from still-IQ wrappers and actual MCC-related control consumers. The next evidence must distinguish:

1. a live producer/caller of the recovered full control API;
2. an alternate partial/direct register or IQ-loading route;
3. a present but unused driver function and possibly bypassed/default hardware state.

None of these alternatives is declared proven by this note.

## Renderer policy

No renderer changes. Preserve DIRECTK1A with identity CC0, frozen RENDER1H downstream behavior, inactive Cat25/YBLEND, and the existing Cat42 direct Q9 policy / bounded hardware-exactness flag. Do not create, fit, or substitute MCC coefficients.

## CI housekeeping

The initial entry-audit run `35495207097` passed four ARM branch-decoder checks but failed before firmware analysis because the shallow checkout lacked the pinned acquisition commit. Commit `9ffca110e53458a8184f1f1f1b7562978c2cf88b` explicitly fetches that commit before reading the frozen acquisition recipe. The subsequent canonical acquisition and analysis succeeded.
