from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "render_xiaomi_m11_controlled.py"
spec = importlib.util.spec_from_file_location("render_xiaomi_m11_controlled", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ControlledXiaomiM11RunnerTests(unittest.TestCase):
    def _record(self):
        historical = json.loads(module.HISTORICAL_MAIN.read_text())
        return {
            "EXIF:AsShotNeutral": "0.5 1.0 0.75",
            "EXIF:CalibrationIlluminant1": 21,
            "EXIF:CalibrationIlluminant2": 17,
            "EXIF:ColorMatrix1": historical["color_matrix_d65"],
            "EXIF:ColorMatrix2": historical["color_matrix_A"],
            "EXIF:ForwardMatrix1": historical["forward_matrix_raw_both_illuminants"],
            "EXIF:ForwardMatrix2": historical["forward_matrix_raw_both_illuminants"],
            "EXIF:BlackLevel": 64,
            "EXIF:WhiteLevel": 1023,
            "EXIF:ISO": 100,
            "EXIF:ExposureTime": 0.01,
            "EXIF:FNumber": 1.63,
            "EXIF:FocalLength": 8.72,
        }

    def test_parse_numbers_accepts_rational_strings(self):
        parsed = module.parse_numbers("1/2 -3/4 2", 3)
        np.testing.assert_allclose(parsed, [0.5, -0.75, 2.0])

    def test_missing_camera_calibration_defaults_to_identity(self):
        meta = module.parse_dng_metadata(self._record())
        self.assertTrue(meta.calibration1_defaulted_identity)
        self.assertTrue(meta.calibration2_defaulted_identity)
        np.testing.assert_allclose(meta.calibration1, np.eye(3))
        np.testing.assert_allclose(meta.calibration2, np.eye(3))

    def test_historical_main_continuity_check_matches_recorded_static_metadata(self):
        meta = module.parse_dng_metadata(self._record())
        comparison = module.compare_historical_main(meta)
        self.assertTrue(comparison["illuminants_match"])
        self.assertTrue(comparison["static_matrices_match"])
        self.assertTrue(comparison["historical_main_characterization_match"])
        for delta in comparison["max_abs_deltas"].values():
            self.assertEqual(delta, 0.0)

    def test_source_transform_is_finite_and_white_balance_is_single_stage(self):
        meta = module.parse_dng_metadata(self._record())
        result, diag = module.build_source_transform(meta)
        self.assertEqual(result.camera_to_xyz_d50.shape, (3, 3))
        self.assertTrue(np.all(np.isfinite(result.camera_to_xyz_d50)))
        self.assertGreaterEqual(result.interpolation_factor, 0.0)
        self.assertLessEqual(result.interpolation_factor, 1.0)
        self.assertTrue(diag["live_neutral_white_balance_folded_into_transform"])
        self.assertFalse(diag["additional_downstream_source_wb"])

    def test_reference_bridge_remains_xiaomi_independent(self):
        historical = json.loads(module.HISTORICAL_MAIN.read_text())
        matrix = module.m11_basis.xyz_d50_to_m11_a_reference_wb()
        self.assertEqual(matrix.shape, (3, 3))
        # Guard against accidentally replacing the target bridge with one of the
        # Xiaomi source matrices while wiring the controlled renderer.
        self.assertFalse(np.allclose(matrix, historical["color_matrix_d65"]))
        self.assertFalse(np.allclose(matrix, historical["color_matrix_A"]))
        self.assertFalse(np.allclose(matrix, historical["forward_matrix_raw_both_illuminants"]))


if __name__ == "__main__":
    unittest.main()
