from __future__ import annotations

import importlib.util
import math
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

    def test_matrix_inverse_roundtrip(self) -> None:
        inv = module.inverse3x3(module.CM1)
        product = module.matmul3x3(inv, module.CM1)
        ident = (1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0)
        for actual, expected in zip(product, ident):
            self.assertAlmostEqual(actual, expected, places=12)

    def test_k_m_d_composition(self) -> None:
        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        actual = module.compose_k_m_d(ident, ident, (2, 3, 4))
        self.assertEqual(actual, (2.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 4.0))

    def test_firmware_calibration_q12_exact(self) -> None:
        self.assertEqual(tuple(round(x * 4096) for x in module.CM1), module.CM1_RAW)
        self.assertEqual(tuple(round(x * 4096) for x in module.CM2), module.CM2_RAW)
        self.assertEqual(module.CM1_TEMPERATURE, 2850.0)
        self.assertEqual(module.CM2_TEMPERATURE, 6807.0)

    def test_firmware_temperature_table_preserves_leica_row_325(self) -> None:
        row = module.TEMP_TABLE[19]
        self.assertEqual(row, (325, 0.24792, 0.34655, -2.4681))

    def test_temperature_table_blackbody_point_is_zero_tint(self) -> None:
        # Invert the firmware/DNG 1960-uv conversion for the r=200 row (5000 K).
        _r, u, v, _slope = module.TEMP_TABLE[14]
        den = u - 4.0 * v + 2.0
        xy = (1.5 * u / den, v / den)
        temperature, tint = module.xy_to_temperature_tint(xy)
        self.assertAlmostEqual(temperature, 5000.0, places=8)
        self.assertAlmostEqual(tint, 0.0, places=8)

    def test_reciprocal_temperature_interpolation_endpoints(self) -> None:
        self.assertEqual(module.interpolate_color_matrix(1000.0), module.CM1)
        self.assertEqual(module.interpolate_color_matrix(module.CM1_TEMPERATURE), module.CM1)
        self.assertEqual(module.interpolate_color_matrix(module.CM2_TEMPERATURE), module.CM2)
        self.assertEqual(module.interpolate_color_matrix(10000.0), module.CM2)

    def test_bradford_d50_to_itself_is_identity_to_firmware_precision(self) -> None:
        actual = module.map_white_matrix(module.D50_XY, module.D50_XY)
        ident = (1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0)
        for value, expected in zip(actual, ident):
            self.assertAlmostEqual(value, expected, places=6)

    def test_neutral_solver_recovers_constructed_d50(self) -> None:
        d50_temp, _ = module.xy_to_temperature_tint(module.D50_XY)
        c = module.interpolate_color_matrix(d50_temp)
        neutral = module.matvec3(c, module.xy_to_xyz(module.D50_XY))
        xy, temperature, _tint, solved_c = module.neutral_to_xy(neutral)
        self.assertAlmostEqual(xy[0], module.D50_XY[0], places=12)
        self.assertAlmostEqual(xy[1], module.D50_XY[1], places=12)
        self.assertAlmostEqual(temperature, d50_temp, places=9)
        for actual, expected in zip(solved_c, c):
            self.assertAlmostEqual(actual, expected, places=12)

    def test_awb_gain_conversion_is_signed16_clamped_then_reciprocal(self) -> None:
        self.assertEqual(module.neutral_from_awb_gains(256, 512, 128), (1.0, 0.5, 2.0))
        self.assertEqual(module.neutral_from_awb_gains(0, 2001, 0xFFFF), (256.0, 0.128, 256.0))

    def test_full_dynamic_cc0_regression_from_awb(self) -> None:
        words = module.dynamic_cc0_record_from_awb(512, 256, 384)
        self.assertEqual(
            words,
            (494, -76, 34, -1, 665, -213, 17, -90, 525, 0, 2838),
        )
        self.assertTrue(all(isinstance(x, int) for x in words))

    def test_xyz_to_xy_firmware_fallback_threshold(self) -> None:
        self.assertEqual(module.xyz_to_xy((0.2, 0.3, 0.4)), module.D50_XY)
        x, y = module.xyz_to_xy((0.4, 0.5, 0.2))
        self.assertAlmostEqual(x, 0.4 / 1.1)
        self.assertAlmostEqual(y, 0.5 / 1.1)

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
