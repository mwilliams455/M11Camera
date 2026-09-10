# REALRAW1C — exact ARM AHD export plan

Purpose: close the remaining ARM/x86 AHD numerical parity question for the exact same Xiaomi 15 Ultra DNG without changing the M11 renderer.

Evidence entering REALRAW1C:

- Exact same-byte DNG SHA256: `5f743887ab4dafba76ffe8d865ea40622bd2737fb41b6a2d9bc40c1f11f08e2a`.
- Android ARM and desktop x86 unpacked mosaic SHA256 are byte-identical: `51e6dc1fa45f1de32658b49034e35be2adbe39f255af1e3d131c593319ae7656`.
- Android ARM AHD SHA256: `d27636e2f86f120a7c0cd278ab150c7a68423f242c97bfc4e0460faf49557dcf`.
- Desktop x86 rawpy 0.27.1 / LibRaw 0.22.1 AHD SHA256: `884894d7c8e1844d07ef21554a7349664a30f21a301863005ce7a6ae96857b71`.
- Exact pinned LibRaw commit `b860248a89d9082b8e0a1e202e516f46af9adb29` built with GCC 13 and Clang 18 on x86 produces the same desktop AHD bytes/hash, isolating the residual difference to the ARM/Android execution environment rather than rawpy packaging or host compiler family.

REALRAW1C should add a separate diagnostic export path that:

1. Keeps the existing identify-only JNI path decode-free.
2. Uses the same narrow Xiaomi identity/geometry/decoder gate as REALRAW1B.
3. Uses the exact frozen rawpy 0.27.1 LibRaw parameters and full-resolution AHD.
4. Writes the resulting 16-bit interleaved RGB AHD bitmap to a user-selected output file as gzip-compressed little-endian bytes.
5. Does not invoke the M11 renderer.
6. Reports source SHA, AHD SHA, dimensions, sample count, uncompressed byte count, compressed byte count and timing.
7. Allows the derived gzip file to be compared privately against the desktop oracle for exact per-sample error statistics.

This is a diagnostic-only boundary closure step, not production rendering.
