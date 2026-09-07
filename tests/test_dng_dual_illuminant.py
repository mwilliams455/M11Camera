from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "renderer" / "source_adapter" / "dng_dual_illuminant.py"
spec = importlib.util.spec_from_file_location("dng_dual_illuminant", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class DngDualIlluminantTests(unittest.TestCase):
    def test_forward_matrix_normalization_maps_white_to_d50(self) -> None:
        fm = np.array(
            [
                [0.6328125, 0.109375, 0.21875],
                [0.21875, 0.7578125, 0.0234375],
                [-0.0390625, -0.453125, 1.3203125],
            ]
        )
        normalized = module.normalize_forward_matrix(fm)
        mapped = normalized @ np.ones(3)
        np.testing.assert_allclose(mapped, module.D50_XYZ, rtol=0, atol=1e-7)

    def test_xiaomi_historical_forward_matrix_matches_recorded_normalization(self) -> None:
        raw = np.array(
            [
                [0.6328125, 0.109375, 0.21875],
                [0.21875, 0.7578125, 0.0234375],
                [-0.0390625, -0.453125, 1.3203125],
            ]
        )
        expected = np.array(
            [
                [0.63496098, 0.10974634, 0.21949268],
                [0.21875, 0.7578125, 0.0234375],
                [-0.03891038, -0.45136038, 1.31517075],
            ]
        )
        np.testing.assert_allclose(
            module.normalize_forward_matrix(raw), expected, rtol=0, atol=2e-8
        )

    def test_color_matrix_is_not_forward_normalized(self) -> None:
        cm = np.array(
            [
                [1.28125, -0.484375, -0.2265625],
                [-0.5859375, 1.59375, 0.140625],
                [-0.046875, 0.1796875, 0.703125],
            ]
        )
        wrongly_normalized = module.normalize_forward_matrix(cm)
        self.assertFalse(np.allclose(wrongly_normalized, cm))

        # With identical endpoints, interpolation can run without modifying the
        # supplied ColorMatrix. This is a convention regression guard, not a
        # claim about a real scene neutral.
        cal = np.eye(3)
        factor = module.find_dng_interpolation_factor(21, 17, cal, cal, cm, cm, [1, 1, 1])
        self.assertTrue(np.isfinite(factor))
        np.testing.assert_array_equal(
            cm,
            np.array(
                [
                    [1.28125, -0.484375, -0.2265625],
                    [-0.5859375, 1.59375, 0.140625],
                    [-0.046875, 0.1796875, 0.703125],
                ]
            ),
        )

    def test_identity_calibration_and_neutral_reduce_to_interpolated_forward(self) -> None:
        # Normalized diagonal ForwardMatrices that both map [1,1,1] to D50.
        fm1 = np.diag(module.D50_XYZ)
        fm2 = np.diag(module.D50_XYZ)
        cal = np.eye(3)
        transform, reference_neutral = module.calculate_camera_to_xyz_d50_transform(
            fm1, fm2, cal, cal, [1, 1, 1], 0.37
        )
        np.testing.assert_allclose(reference_neutral, np.ones(3), atol=1e-12)
        np.testing.assert_allclose(transform, fm1, atol=1e-12)

    def test_live_neutral_is_folded_into_transform(self) -> None:
        fm = np.diag(module.D50_XYZ)
        cal = np.eye(3)
        transform, reference_neutral = module.calculate_camera_to_xyz_d50_transform(
            fm, fm, cal, cal, [0.5, 1.0, 0.25], 0.5
        )
        np.testing.assert_allclose(reference_neutral, [0.5, 1.0, 0.25], atol=1e-12)
        expected_wb = np.diag([2.0, 1.0, 4.0])
        np.testing.assert_allclose(transform, fm @ expected_wb, atol=1e-12)

    def test_unsupported_illuminant_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported reference illuminant"):
            module.find_dng_interpolation_factor(
                999, 17, np.eye(3), np.eye(3), np.eye(3), np.eye(3), [1, 1, 1]
            )

    def test_apply_camera_to_xyz_shape(self) -> None:
        rgb = np.array([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
        out = module.apply_camera_to_xyz(rgb, np.eye(3))
        np.testing.assert_allclose(out, rgb)


if __name__ == "__main__":
    unittest.main()
