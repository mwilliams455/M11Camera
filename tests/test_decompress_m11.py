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


def encode_base128(value: int) -> bytes:
    if value < 0:
        raise ValueError
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    out = bytearray()
    for i, group in enumerate(groups):
        if i != len(groups) - 1:
            out.append(group | 0x80)
        else:
            out.append(group)
    return bytes(out)


def build_firmware(body: bytes, expected_size: int, body_off: int = 0x40) -> bytes:
    header = bytearray(body_off)
    struct.pack_into("<I", header, 0x04, body_off)
    struct.pack_into("<I", header, 0x0C, expected_size)
    struct.pack_into("<I", header, 0x14, len(body))
    header[0x18:0x28] = hashlib.md5(body).digest()
    return bytes(header) + body


class M11DecompressorTests(unittest.TestCase):
    def test_base128_examples_from_real_firmware(self) -> None:
        examples = {
            b"\x10": 16,
            b"\x90\x00": 2048,
            b"\xA0\x00": 4096,
            b"\xC0\x00": 8192,
            b"\x81\x80\x00": 16384,
        }
        for encoded, expected in examples.items():
            value, end = module.read_base128_uint(encoded, 0)
            self.assertEqual(value, expected)
            self.assertEqual(end, len(encoded))
            self.assertEqual(encode_base128(expected), encoded)

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
        firmware = build_firmware(body, len(expected))

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "synthetic.FW"
            dst = tmp / "synthetic_unpacked.bin"
            src.write_bytes(firmware)

            module.decompress_firmware(src, dst)
            self.assertEqual(dst.read_bytes(), expected)

    def test_three_byte_length_and_offset_backreference(self) -> None:
        marker = 0xF0
        seed = b"A" * 16384
        # A genuine M11-P 2.6.1 stream uses three-byte values such as 81 80 00.
        # Copy one 16 KiB block from 16 KiB back to exercise both length and offset.
        body = bytes([marker]) + seed + bytes([marker]) + encode_base128(16384) + encode_base128(16384)
        expected = seed + seed
        firmware = build_firmware(body, len(expected))

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "three_byte.FW"
            dst = tmp / "three_byte_unpacked.bin"
            src.write_bytes(firmware)
            module.decompress_firmware(src, dst)
            self.assertEqual(dst.read_bytes(), expected)

    def test_overlapping_backreference(self) -> None:
        marker = 0xF0
        # Emit A, then copy eight bytes with offset 1. Dynamic tail-copy semantics
        # must produce eight more A bytes.
        body = bytes([marker, ord("A"), marker, 8, 1])
        expected = b"A" * 9
        firmware = build_firmware(body, len(expected))
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "overlap.FW"
            dst = tmp / "overlap.bin"
            src.write_bytes(firmware)
            module.decompress_firmware(src, dst)
            self.assertEqual(dst.read_bytes(), expected)

    def test_rejects_out_of_range_backreference(self) -> None:
        marker = 0xF0
        body = bytes([marker, ord("A"), marker, 2, 5])
        firmware = build_firmware(body, 3)

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "bad.FW"
            dst = tmp / "bad.bin"
            src.write_bytes(firmware)
            with self.assertRaisesRegex(ValueError, "bad offset"):
                module.decompress_firmware(src, dst)


if __name__ == "__main__":
    unittest.main()
