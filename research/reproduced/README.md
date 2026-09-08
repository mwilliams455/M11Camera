# Reproduced primary M11-P firmware evidence

This directory records compact hashes and metadata for artifacts reproduced from a locally supplied original Leica M11-P 2.6.1 updater.

Proprietary firmware binaries are never committed.

Canonical regeneration flow:

```text
LEICA_M11-P_2.6.1.FW
→ tools/decompress_m11.py
→ 97,644,400-byte unpacked firmware body
→ tools/extract_m11p_r2y_forensics.py
→ derived JSON/CSV tables + manifest
```

See:

- `M11P_261_PRIMARY_HASHES.json`
- `../../docs/research/R0_PRIMARY_FIRMWARE_REPRODUCTION_20260908.md`
- `../../docs/research/EVIDENCE_STATUS.md`

Primary table recovery is complete. Consumer order, gamma placement, fixed-point clamp/rounding behavior and final output transfer remain separate reverse-engineering tasks.
