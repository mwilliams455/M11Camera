from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "renderer" / "m11_core" / "reference_basis.py"
spec = importlib.util.spec_from_file_location("m11_reference_basis", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class M11ReferenceBasisTests(unittest.TestCase):
    def test_genuine_m11_color_matrix_a_q12_exact(self) -> None:
        q12 = np.rint(module.M11_COLOR_MATRIX_A * 4096.0).astype(int)
        np.testing.assert_array_equal(
            q12,
            np.array(
                [[2358, -546, -66], [-2488, 6300, 1785], [-403, 797, 3504]],
                dtype=int,
            ),
        )

    def test_derived_bridge_matches_12dng_regression_target(self) -> None:
        actual = module.xyz_d50_to_m11_a_reference_wb()
        np.testing.assert_allclose(
            actual,
            module.RECORDED_REFERENCE_XYZ_D50_TO_M11_A_WB,
            rtol=0,
            atol=1.0e-8,
        )

    def test_bridge_inverse_roundtrip(self) -> None:
        xyz_to_ref = module.xyz_d50_to_m11_a_reference_wb()
        ref_to_xyz = module.m11_a_wb_camera_to_xyz_d50()
        np.testing.assert_allclose(ref_to_xyz @ xyz_to_ref, np.eye(3), atol=1e-12)

    def test_apply_supports_vectors_and_images(self) -> None:
        v = np.array([0.2, 0.3, 0.1])
        out = module.apply_xyz_d50_to_m11_reference(v)
        np.testing.assert_allclose(out, module.xyz_d50_to_m11_a_reference_wb() @ v)

        image = np.stack([v, v * 2]).reshape(1, 2, 3)
        mapped = module.apply_xyz_d50_to_m11_reference(image)
        self.assertEqual(mapped.shape, image.shape)


if __name__ == "__main__":
    unittest.main()
