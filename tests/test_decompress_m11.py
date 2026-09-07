from __future__ import annotations

import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "decompress_m11.py"
spec = importlib.util.spec_from_file_location("decompress_m11", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class M11DecompressorTests(unittest.TestCase):
    def test_literal_escape_and_backreference(self) -> None:
        marker = 0xF0
        # Decoder skips the first marker byte, then emits:
        # ABC + backref(length=3, offset=3) + literal marker + '!'
        # => ABCABC\xF0!
        body = bytes(
            [
                marker,
                ord("A"),
                ord("B"),
                ord("C"),
                marker,
                3,
                3,
                marker,
                0,
                ord("!"),
            ]
        )
        expected = b"ABCABC" + bytes([marker]) + b"!"

        body_off = 0x40
        header = bytearray(body_off)
        struct.pack_into("<I", header, 0x04, body_off)
        struct.pack_into("<I", header, 0x0C, len(expected))
        struct.pack_into("<I", header, 0x14, len(body))
        header[0x18:0x28] = hashlib.md5(body).digest()
        firmware = bytes(header) + body

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "synthetic.FW"
            dst = tmp / "synthetic_unpacked.bin"
            src.write_bytes(firmware)

            module.decompress_firmware(src, dst)
            self.assertEqual(dst.read_bytes(), expected)

    def test_rejects_out_of_range_backreference(self) -> None:
        marker = 0xF0
        body = bytes([marker, ord("A"), marker, 2, 5])
        body_off = 0x40
        header = bytearray(body_off)
        struct.pack_into("<I", header, 0x04, body_off)
        struct.pack_into("<I", header, 0x0C, 3)
        struct.pack_into("<I", header, 0x14, len(body))
        header[0x18:0x28] = hashlib.md5(body).digest()

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "bad.FW"
            dst = tmp / "bad.bin"
            src.write_bytes(bytes(header) + body)
            with self.assertRaisesRegex(ValueError, "bad offset"):
                module.decompress_firmware(src, dst)


if __name__ == "__main__":
    unittest.main()
