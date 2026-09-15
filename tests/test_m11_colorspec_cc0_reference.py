from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "m11_colorspec_cc0_reference.py"
spec = importlib.util.spec_from_file_location("m11_colorspec_cc0_reference", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class M11ColorSpecCC0ReferenceTests(unittest.TestCase):
    def test_round_half_away_from_zero(self) -> None:
        self.assertEqual(module.round_away(0.49), 0)
        self.assertEqual(module.round_away(0.5), 1)
        self.assertEqual(module.round_away(1.5), 2)
        self.assertEqual(module.round_away(-0.49), 0)
        self.assertEqual(module.round_away(-0.5), -1)
        self.assertEqual(module.round_away(-1.5), -2)

    def test_matrix_multiply_is_row_major(self) -> None:
        a = (1, 2, 3, 4, 5, 6, 7, 8, 9)
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        self.assertEqual(module.matmul3x3(a, ident), tuple(float(x) for x in a))
        self.assertEqual(module.matmul3x3(ident, a), tuple(float(x) for x in a))

    def test_k_m_d_composition(self) -> None:
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        actual = module.compose_k_m_d(ident, ident, (2, 3, 4))
        self.assertEqual(actual, (2.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 4.0))

    def test_shift_selection_matches_firmware_policy(self) -> None:
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        self.assertEqual(module.choose_shift(ident), 0)
        self.assertEqual(module.choose_shift((5, 0, 0, 0, 1, 0, 0, 0, 1)), 1)
        self.assertEqual(module.choose_shift((20, 0, 0, 0, 1, 0, 0, 0, 1)), 3)

    def test_identity_quantizes_to_q9(self) -> None:
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        words = module.encode_record_words(ident, 7.5)
        self.assertEqual(words[:9], (512, 0, 0, 0, 512, 0, 0, 0, 512))
        self.assertEqual(words[9], 0)
        self.assertEqual(words[10], 8)

    def test_shift_three_fallthrough_still_clamps(self) -> None:
        m = (100, 0, 0, 0, -100, 0, 0, 0, 1)
        words = module.encode_record_words(m, -2.5)
        self.assertEqual(words[9], 3)
        self.assertEqual(words[0], 2047)
        self.assertEqual(words[4], -2048)
        self.assertEqual(words[10], -3)

    def test_record_is_44_bytes_and_roundtrips(self) -> None:
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        record = module.encode_record_bytes(ident, 1)
        self.assertEqual(len(record), 44)
        self.assertEqual(module.decode_record_bytes(record), module.encode_record_words(ident, 1))


if __name__ == "__main__":
    unittest.main()
