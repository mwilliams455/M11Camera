from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "m11_romfs_probe.py"
spec = importlib.util.spec_from_file_location("m11_romfs_probe", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
# dataclasses resolves postponed annotations through sys.modules during class
# construction, so register the dynamically loaded module before exec_module.
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def synthetic_romfs(volume_name: bytes = b"M11TEST") -> bytes:
    """Build a tiny structurally valid ROMFS root containing /r2y.bin."""
    label = volume_name + b"\x00"
    root_rel = module.align16(16 + len(label))
    root_name_end = root_rel + 16 + 2  # '.\0'
    child_rel = module.align16(root_name_end)
    child_name = b"r2y.bin\x00"
    child_data_rel = module.align16(child_rel + 16 + len(child_name))
    payload = b"R2Y!"
    size = module.align16(child_data_rel + len(payload))

    out = bytearray(size)
    out[0:8] = module.ROMFS_MAGIC
    struct.pack_into(">I", out, 8, size)
    struct.pack_into(">I", out, 12, 0)  # checksum placeholder for parser tests
    out[16 : 16 + len(label)] = label

    # Root directory. With no next sibling, next pointer contains only type=1.
    struct.pack_into(">IIII", out, root_rel, 1, child_rel, 0, 0)
    out[root_rel + 16 : root_rel + 18] = b".\x00"

    # Single regular child. With no next sibling, next pointer contains type=2.
    struct.pack_into(">IIII", out, child_rel, 2, 0, len(payload), 0)
    out[child_rel + 16 : child_rel + 16 + len(child_name)] = child_name
    out[child_data_rel : child_data_rel + len(payload)] = payload
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
        self.assertEqual(info.root_header_rel, 32)
        self.assertEqual(len(info.sha256), 64)

    def test_structured_walk_finds_r2y(self) -> None:
        image = synthetic_romfs()
        info = module.parse_romfs(image, 0, len(image))
        entries = module.walk_romfs(image, info.root_header_rel)
        self.assertEqual([entry.path for entry in entries], ["/", "/r2y.bin"])

        matches = module.find_entries(entries, "r2y.bin")
        self.assertEqual(len(matches), 1)
        entry = matches[0]
        self.assertEqual(entry.type_name, "file")
        self.assertEqual(entry.size, 4)
        self.assertEqual(module.entry_bytes(image, entry), b"R2Y!")

        absolute = module.find_entries(entries, "/r2y.bin")
        self.assertEqual(absolute, matches)

    def test_find_romfs_and_ascii(self) -> None:
        image = synthetic_romfs()
        data = b"A" * 5 + image + b"B" * 7 + image
        self.assertEqual(module.find_romfs(data), [5, 5 + len(image) + 7])
        hits = module.search_ascii(data, "r2y.bin")
        self.assertEqual(len(hits), 2)

    def test_rejects_bad_magic(self) -> None:
        with self.assertRaisesRegex(ValueError, "magic missing"):
            module.parse_romfs(b"X" * 64, 0)

    def test_rejects_unaligned_file_header(self) -> None:
        image = synthetic_romfs()
        with self.assertRaisesRegex(ValueError, "unaligned"):
            module.parse_entry(image, 33, "/bad")


if __name__ == "__main__":
    unittest.main()
