# M11-P 2.6.1 — MCC RDMA address-owner closure 1A

Date: 2026-09-20
Canonical unpacked SHA-256: `28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`

## Result

The previously unproven 0x78C size lead is closed separately as a sequential record ordinal. This continuation recovered a genuinely MCC-owned static object through a named firmware API and its exact return-expression instructions. The recovered objects contain **hardware register addresses, not Leica colour coefficients**.

This result does not establish a live still-photo MCC invocation, an active non-identity MCC transform, or an inactive/bypassed MCC stage. Do not add or remove a rendering operation on its basis.

## Corrected assertion-string census

Run `35495642324`, commit `31c5e1041efd0bab5a7766f9516a70c2f4e3f1d7`, artifact `10600294225`:

- accepted LF, CR and TAB within firmware C strings;
- passed four C-string unit tests;
- recovered the known `Im_R2Y_Ctrl_Multi_Axis` assertion;
- resolved that assertion's adjacent MOVW/MOVT reference to the known entry `0x01B2D324`.

The earlier empty string/API result from run `35495431640` is invalid: the first parser rejected newline-terminated SDK assertion strings. Its disassembly remains useful, but its negative string census is not evidence of absence.

Correctly identified entries include:

| File entry | Asserted API |
| --- | --- |
| `0x01B2397C` | `Im_R2Y_Stop` |
| `0x01B1B9C8` | `Im_R2Y_Init` |
| `0x01B1CDA4` | `Im_R2Y_Ctrl` |
| `0x01B2D324` | `Im_R2Y_Ctrl_Multi_Axis` |
| `0x01B60320` | `Im_R2Y_Ctrl_BeforeTone_Offset` |
| `0x01B6B388` | `Im_R2Y_Get_RdmaAddr_Multi_Axis_Cntl` |

In the bounded A32 candidate-code region `[0x01600000, 0x01C90000)`, no direct B/BL candidate to either MCC writer or MCC RDMA getter was found. This is not an exclusion of indirect dispatch, non-adjacent address constructions, different instruction states, or alternate programming paths.

Boundary correction: MCC returns at `0x01B6031C`. `0x01B60320` is the next API entry. The call at `0x0172D3B0` to `0x01B60320` is therefore BeforeTone Offset, not MCC.

## Exact owned-object provenance

The getter at `0x01B6B388` checks pipe range, then executes:

```text
01B6B3D8  ldrb r3,[fp,#-5]       ; pipe
01B6B3DC  movw r2,#0x7F4         ; per-pipe stride
01B6B3E0  mul r2,r2,r3
01B6B3E4  movw r3,#0x6EB8
01B6B3E8  movt r3,#0x42B6
01B6B3EC  add r2,r2,r3
01B6B3F0  ldr r3,[fp,#-0xC]      ; output pointer
01B6B3F4  str r2,[r3]
```

Thus:

```text
returned runtime address = 0x42B66EB8 + pipe * 0x7F4
runtime-to-file delta    = 0x3FAA87D0
file base               = 0x030BE6E8
```

The new probe byte-checks the complete return-expression instruction sequence before extracting data. This is API/argument/instruction provenance, not a numeric-size hypothesis.

## Lossless extraction and classification

Run **`35495941014`**, commit **`b10ec4c899fa6aa1f56b206fb586494b9909236a`**: **SUCCESS**.
Artifact **`10601025102`**, name `r2a-m11-mcc-entryaudit1a`.
ZIP SHA-256: `a6dfdc4f90ba2f741984ec889405061d979833b5fee1a3405076a138775edd92`.

| Pipe argument | File object | Bytes | u32 entries | Address range |
| --- | --- | --- | --- | --- |
| 0 | `0x030BE6E8` | 2036 / `0x7F4` | 509 | `0x28419000..0x284199B4` |
| 1 | `0x030BEEDC` | 2036 / `0x7F4` | 509 | `0x28519000..0x285199B4` |
| 2 | `0x030BF6D0` | 2036 / `0x7F4` | 509 | `0x28619000..0x286199B4` |

Each object contains 509 distinct, four-byte-aligned addresses. Every corresponding pipe-1 entry equals pipe-0 plus `0x00100000`; every pipe-2 entry equals pipe-0 plus `0x00200000`.

The register offset sequences are identical across all three objects. They are register-destination maps for the MCC hardware bank, not a 0x78C `CtrlMultiAxis` value structure and not the values to write there.

Extracted object SHA-256s:

```text
pipe 0 b78eacf6015c9269051093cc7c5e4b63c5cc3e24a74b3676a25eecb9da32602d
pipe 1 0eba4fc2e5b092953f9034b7e990e50c24287fb3df3f02e46b6d377ba919b37a
pipe 2 ba1e4dd8028548a11740bfc9db16d596e89c51da706c36353db363874a5df4e0
```

## Reference results and their limits

The bounded adjacent A32 MOVW/MOVT scan found one reference into the entire three-object range: `0x01B6B3E4`, in the getter itself.

The aligned raw-word scan found 36 numeric values falling anywhere within the static/runtime ranges, but no exact-base pointer. These are not automatically usable references. Most are outside the candidate code window; one numerical match inside it is at `0x01C53E1C` with value `0x030BEB0A` (offset `0x422`, not a u32-aligned address-array element). No such raw hit was promoted to a consumer.

No still-path consumer of the object has been established.

## Common-mode field mapping, not an enable proof

The firmware `Im_R2Y_Ctrl` source loads and register updates independently show:

| Control byte | Firmware load | perPipeBase+0x4094 bit | Public name |
| --- | --- | --- | --- |
| `+0x65` | `0x01B1D314` | 0 | YCFBYP |
| `+0x66` | `0x01B1D34C` | 1 | YCFPDD |
| `+0x67` | `0x01B1D388` | 4 | MCCSL |
| `+0x68` | `0x01B1D3C4` | 5 | MCC1BM |

The Leica control builder at `0x0172C19C` initializes these bytes to `[0,1,0,0]` at `0x0172C1D4`, `0x0172C1E0`, `0x0172C1EC`, `0x0172C1F8`. This corroborates the established MCC-after-CC0 selection; it does not disclose non-identity MCC values or establish still-path activation.

Public semantic cross-check only (not a Leica coefficient source):

- repository `ZMlogicL/companyTask`, commit `f5fc84bd5c475f4c15017b7bff749f81c3618287`;
- `MILB_API/Project/ImageMacro/src/imr2y.c`, lines 555-625, common-mode field writes;
- `MILB_API/Project/ImageMacro/src/imr2yctrl.h`, MCC placement constants;
- `MILB_API/Project/ImageMacro/src/imr2yutility.h`, `im_r2y_utility_get_rdma_addr_multi_axis_cntl`, returns `const CtrlRdmaMcycAddr**` and identifies an address array;
- `MILB_API/MILB_Header/Project/Image/src/jdsr2yf2e2.h`, R2YMODE bit layout.

## Next evidence gate

Do not search for colour values inside this address-only map. Use its 509 normalized register destinations as a verified signature while tracing actual still IQ/RDMA register-program construction. Recover the paired value source and prove its still-path invocation, or establish the live bypass/default state through primary control-flow/register evidence.

Indirect API dispatch remains possible. Driver/library presence plus an after-CC0 selector is insufficient to insist that a missing non-identity Leica MCC object must exist.

Preserve DIRECTK1A, identity CC0, all frozen RENDER1H downstream math, inactive Cat25 and the current bounded Cat42 conventions. This research changes no app/JNI/renderer code and produces no new APK.
