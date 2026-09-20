# M11-P 2.6.1 MCCSTATE1A — bounded register census and R2Y file-cache owner

Date: 2026-09-20. Research only. No renderer, JNI, app or photographic-policy changes.

## Provenance and execution split

Continuation baseline: `af7259fcd5d9069fa2ac9357afc9403ceb99f9b8`.
Research branch: `work/mcc-stillpath1a-20260920`.

Canonical unpacked firmware SHA-256:
`28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c`.

Evidence-export workflow: `.github/workflows/r2a-m11-mccstate1a.yml`.
Successful commit: `4c5da57b9a859434c206f3b802c7e5da72c6fffb`.
Successful run: `35498123088`.
Artifact: `10601722322`, `r2a-m11-mccstate1a`.
Artifact ZIP SHA-256:
`b4b574f3596019597b354f00d3aeeeca0b73fd3137cf4dac6fa4e4f8ed8435c6`.

CI acquired and verified the complete canonical firmware, checked three instruction anchors and exported four bounded file slices. The downloaded ZIP digest and all four slice lengths/digests were verified locally. The register scan, function reconstruction and 29 new tests described below ran locally against those slices, not in the export CI job. The complete local verifier/tests/results are in `M11_MCCSTATE1A_CONTINUATION_20260920.zip`; they are not committed by this research-note change.

The initial export run `35498067159` failed on an incorrectly specified return-opcode gate. The known MCC return at `0x01B6031C` is `POP {fp,pc}`, bytes `0088bde8`, not `BX lr`. The corrected export run above passed. This changes no established function address or rendering behavior.

## 1. Bounded MCC register-access census

Scan interval: `[0x01B18000,0x01B6DB00)`.

The analyzer follows straight-line A32 address computations seeded by loads from the established R2Y register-pointer array at runtime `0x43201224`. It handles constant construction and base-plus-offset operations, kills unknown written registers, and discards state across branches, calls, predicated instructions and PC writes. Writeback addressing is not guessed. It never substitutes guessed live RAM values from a firmware-file offset.

Results:

| Measurement | Result |
| --- | ---: |
| Recognized MCC store instruction sites | 950 |
| Recognized MCC stores outside `[0x01B2D324,0x01B60320)` | 0 |
| Distinct per-pipe MCC destination offsets | 509 |
| Difference from getter-owned RDMA destination set | Empty |

The 509 offsets exactly equal the pipe-0 RDMA object's address words minus `0x28418000`. The independently owned object at file `0x030BE6E8`, length `0x7F4`, retains SHA-256 `b78eacf6015c9269051093cc7c5e4b63c5cc3e24a74b3676a25eecb9da32602d`.

This is an exact destination-set comparison, not just a matching count. The older report of 948 recognized writes came from a different probe; 950 here counts recovered store instructions, not coefficient entries or newly discovered control parameters. Multiple stores can update fields of the same register.

An additional adjacent MOVW/MOVT census in `[0x01560000,0x01C90000)` finds no immediate construction directly inside the three physical MCC banks. That narrowly scoped negative result does not exclude other address-building patterns, passed-in pointers or indirect writes.

**Limit:** this is an underapproximating static address-pattern census, not an exhaustive whole-program may-write analysis. All recognized MCC stores are in the known writer; this does not establish that no other runtime mechanism can write MCC.

## 2. Forty-one previously external targets now have own-function identities

The previous still-job reconstruction had 51 external target addresses. For 41 R2Y targets, the new local analysis follows each function's internal A32 control flow while retaining its calls as boundaries. Each has one consistent `Im_R2Y_*` identity recovered from assertion-string references on that function's reachable instruction set.

They cover output-bank and resize controls, stop/trimming/histogram, input offset/WB, CC0, before-tone, tone/gamma/CC1, YC, noise/edge/chroma controls and table setters. None has a recognized MCC-bank access in the new census. The verification package lists all 41 addresses, assertions, graphs and counts.

The one newly encountered indirect branch was in `Im_R2Y_Set_Gamma_Table`:

```text
0x01B69DB0  CMP r3,#4
0x01B69DB4  LDRLS pc,[pc,r3,LSL #2]
```

Its five relocated table targets are `0x01B69DD0`, `0x01B69E04`, `0x01B69E38`, `0x01B69E6C`, `0x01B69EA0`. Instruction words, preceding comparison, alignment and containing routine are gated. It is an internal gamma-table selector, not a recovered MCC API dispatch. With that table resolved, the 41 single-function graphs have zero unresolved internal transfers. Their callees remain open boundaries.

Ten other targets in the previous frontier are retained explicitly:
`01566D04`, `01566D94`, `01566DE4`, `01679B58`, `017F15A4`, `017F2E74`, `019D8838`, `01A1C280`, `01A1C3A0`, `01C4E068`.

They include interrupt/locking, logging, global-value queries, arithmetic, clock-management and memory-fill paths. These semantic classifications do not establish complete call contracts or exclude generic writes through caller-supplied pointers. In particular, `019D8838` and `01C4E068` are reached in Thumb state; do not treat an A32 disassembly of those bytes as executable evidence.

## 3. Primary map8 pointer loading path identified

The existing map8 leaf at `0x0178C4DC` returns the primary pointer at `0x43379A68` if nonzero, otherwise the fallback at `0x43379A6C`.

A concrete producer of the primary slot is now identified:

```text
0x0178D120  R2Y loading wrapper
0x0178D14C  loads output-slot address from literal at 0x0178D164
            literal value = 0x43379A68
0x0178D150/154 constructs 0x42B99960
            verified string = img/data/r2y.bin
0x0178D15C  tail-branches to cached loader 0x0178AC68
```

The cached loader returns an already nonzero slot without reloading. On the uncached path it obtains a size, allocates a buffer and stores the allocation result through the supplied slot at `0x0178ACAC`. The subsequent read path uses that buffer; on a read failure it frees the buffer and clears the slot at `0x0178ACD8`.

The update/delete routine at `0x0178E190` accesses the same `root+0x34` primary slot, releases an existing cached allocation and clears the slot at `0x0178E1C8`. It then uses the same filename for write/delete operations. Two A32 branch candidates call the loading wrapper at `0x0178D3AC` and `0x0178FC14`; no physical-device execution is asserted.

**This establishes the primary slot's file-loading provenance, not an MCC coefficient source.** No new `r2y.bin` payload or coefficient object was recovered in this continuation. The fallback slot's initializer and its actual runtime contents remain unknown.

## 4. RAM/file mapping trap explicitly avoided

The exporter includes two small file ranges selected by subtracting the previously validated string/data delta from candidate RAM addresses. Those slices are not live RAM dumps. The delta's success for named strings, known static objects and verified jump tables does not establish a mapping for arbitrary globals or BSS.

Do not read those file bytes as the runtime R2Y base-pointer array, map8 pointer values, initialized fallback state or MCC defaults. A real initialization/copy/relocation chain is needed first.

## 5. Local tests and outcome

All 29 new local tests passed. They cover synthetic pointer seeds, unknown RAM, predicated/clobbered registers, branches/calls, unsupported writeback, instruction state, conditional returns, missing bytes and slice mutation. Canonical controls check the return opcode, primary pointer/filename chain, map8 leaf, gamma switch, 950-store interval and exact 509-destination RDMA match.

These tests validate the implementation and the stated canonical regression checks. They do not provide device execution, a full-firmware emulation or a hardware register oracle.

## 6. Next gate and renderer freeze

The remaining investigation is actual MCC register-state provenance, especially earlier initialization, alternative passed-pointer/RDMA programming and reset/retention behavior. Trace the fallback-slot producer and actual initialized-data mapping only through proven instructions/copy records; do not infer them from the string relocation delta.

The important change in direction is evidential: there is still no reason to insist that a missing non-identity MCC transform must exist. Conversely, the bounded negative scan does not prove bypass or identity. Recover real values and their still-path use, or obtain primary reset/retention evidence, before changing the renderer.

Preserve DIRECTK1A, identity CC0, frozen RENDER1H downstream, inactive Category25, Cat42 code/512 and hardware-exact=false. No guessed MCC, LUT fitting, exposure compensation, HDR or local tone changes. No new APK.
