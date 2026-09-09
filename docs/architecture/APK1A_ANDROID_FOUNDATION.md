# M11 APK1A — controlled-render Android foundation

APK1A begins Android development without changing the evidence status of the M11 renderer.

## Scope

APK1A is an offline diagnostic/research app, not yet a Camera2/Photon capture build.  Its first purpose is to make the existing controlled Xiaomi DNG -> M11 reference-render path portable to Android one validated stage at a time.

Initial Android shell:

1. accepts a user-selected DNG through Android's Storage Access Framework;
2. freezes the three known SRO Q9 records as firmware-evidence constants;
3. carries the exact recovered half-away-from-zero Q9 quantizer;
4. represents third-matrix placement as an explicit unresolved research variable;
5. builds/tests independently of the capture pipeline.

## Evidence boundary

Correct third M11 SRO Q9 target:

```
 212  -165   -71
 -73   676    85
 -27   174   285
```

The old target `[212,-207,-5,-620,1576,68,43,335,686]` is stale and must not be reintroduced.

Known storage/quantization does **not** prove the third matrix's pixel-domain consumer.  APK1A therefore does not hard-wire the third matrix into the render graph.

## Port sequence

The Python implementation remains the numerical oracle.  Port in this order:

1. DNG CFA payload decode and metadata capture.
2. Xiaomi 15 Ultra main-camera source adapter with fixture parity.
3. Existing trusted M11 reference-render stages, preserving stage boundaries.
4. Stage-wise hashes/statistics against Python fixtures.
5. Only then enable experimental third-SRO placement modes for controlled A/B renders.
6. Continue firmware work in parallel to replace experimental placement with the proven consumer location and eventually replace the fixed SRO with the exact dynamic Leica white/ColorSpec producer.
7. Add Camera2/Photon capture only after offline parity is stable.

## Non-goals for APK1A shell

- No HDR or multi-frame processing.
- No visual fitting of M11 color/tone.
- No generic CCT approximation presented as Leica white-balance behavior.
- No assumption that `SetWhiteXY` directly outputs the final B2Y Q8 gain triplet.
- No mutation of the current Python reference renderer to make Android easier to match.
