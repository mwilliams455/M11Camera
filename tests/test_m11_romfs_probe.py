from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "m11_romfs_probe.py"
spec = importlib.util.spec_from_file_location("m11_romfs_probe", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def synthetic_romfs(volume_name: bytes = b"M11TEST") -> bytes:
    # Minimal superblock-like image sufficient for the probe: magic, BE size,
    # checksum placeholder, NUL-terminated volume label, aligned/padded payload.
    label = volume_name + b"\x00"
    size = module.align16(16 + len(label)) + 16
    out = bytearray(size)
    out[0:8] = module.ROMFS_MAGIC
    struct.pack_into(">I", out, 8, size)
    struct.pack_into(">I", out, 12, 0)
    out[16 : 16 + len(label)] = label
    out[-8:] = b"r2y.bin\x00"
    return bytes(out)


class M11RomfsProbeTests(unittest.TestCase):
    def test_parse_romfs_header(self) -> None:
        image = synthetic_romfs()
        data = b"PREFIX" + image + b"SUFFIX"
        info = module.parse_romfs(data, 6, len(image))
        self.assertEqual(info.offset, 6)
        self.assertEqual(info.declared_size, len(image))
        self.assertEqual(info.recorded_size, len(image))
        self.assertEqual(info.volume_name, "M11TEST")
        self.assertEqual(len(info.sha256), 64)

    def test_find_romfs_and_ascii(self) -> None:
        image = synthetic_romfs()
        data = b"A" * 5 + image + b"B" * 7 + image
        self.assertEqual(module.find_romfs(data), [5, 5 + len(image) + 7])
        hits = module.search_ascii(data, "r2y.bin")
        self.assertEqual(len(hits), 2)

    def test_rejects_bad_magic(self) -> None:
        with self.assertRaisesRegex(ValueError, "magic missing"):
            module.parse_romfs(b"X" * 64, 0)


if __name__ == "__main__":
    unittest.main()
