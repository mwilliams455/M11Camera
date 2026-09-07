# Official Leica M11-P 2.6.1 Firmware Source

**Checked:** 2026-09-07

Leica's official M11-P downloads page still exposes firmware version **2.6.1**.

Official download page:

```text
https://leica-camera.com/en-GB/photography/cameras/m/m11-p-black/downloads
```

Direct firmware payload observed from Leica's site:

```text
https://leica-camera.com/sites/default/files/LEICA_M11-P_2.6.1.FW
```

The firmware binary is proprietary Leica material and must **not** be committed to this public repository. `.gitignore` excludes `*.FW`, `*.fw`, and unpacked firmware binaries.

## Local R0 workflow

After downloading the official firmware locally:

```bash
python tools/decompress_m11.py \
  /path/to/LEICA_M11-P_2.6.1.FW \
  --output /tmp/LEICA_M11-P_2.6.1_unpacked.bin

python tools/m11_romfs_probe.py \
  /tmp/LEICA_M11-P_2.6.1_unpacked.bin \
  --scan \
  --search r2y.bin \
  --carve-dir /tmp/m11p_romfs
```

Expected historical landmarks to verify:

```text
0x00E3A160  recorded size 3,629,024 bytes
0x0333DF70  recorded size 43,912,464 bytes
```

Those landmarks are recorded prior findings and remain non-canonical until reproduced from the locally supplied firmware.

## Evidence policy

The source URL proves where the binary originates; it does **not** prove any internal table semantics. Canonical firmware evidence begins only after the local extractor records source hashes, offsets, decoding rules and output hashes.
