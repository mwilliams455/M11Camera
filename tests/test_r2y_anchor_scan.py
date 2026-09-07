import importlib.util
import struct
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "r2y_anchor_scan.py"
spec = importlib.util.spec_from_file_location("r2y_anchor_scan", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
mod = importlib.util.module_from_spec(spec)
# Python 3.12 dataclasses consult sys.modules while resolving annotations.
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class R2YAnchorScanTests(unittest.TestCase):
    def test_matrix_anchor_little_endian_offset(self):
        payload = (
            b"\xAA" * 13
            + mod.pack_i16(mod.ANCHORS["cc0_q9"], "little")
            + b"\xBB" * 7
        )
        hits = mod.scan_matrix_anchors(payload)
        cc0 = [h for h in hits if h.anchor == "cc0_q9" and h.endian == "little"]
        self.assertEqual(len(cc0), 1)
        self.assertEqual(cc0[0].offset, 13)

    def test_matrix_anchor_big_endian_detected_separately(self):
        payload = b"\x00" * 5 + mod.pack_i16(mod.ANCHORS["category24_ycc"], "big")
        hits = mod.scan_matrix_anchors(payload)
        ycc = [h for h in hits if h.anchor == "category24_ycc"]
        self.assertEqual([(h.endian, h.offset) for h in ycc], [("big", 5)])

    def test_exact_saturation_run(self):
        payload = b"header" + mod.pack_u16(mod.SAT_VALUES, "little") + b"tail"
        hits = mod.scan_saturation_runs(payload)
        strong = [h for h in hits if h.anchor == "category42_sat_run"]
        self.assertEqual(len(strong), 1)
        self.assertEqual(strong[0].endian, "little")
        self.assertEqual(strong[0].offset, len(b"header"))

    def test_no_false_matrix_hit_from_unrelated_data(self):
        payload = struct.pack("<" + "h" * 9, *range(9))
        self.assertEqual(mod.scan_matrix_anchors(payload), [])

    def test_find_all_reports_overlapping_occurrences(self):
        self.assertEqual(mod.find_all(b"AAAA", b"AA"), [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
