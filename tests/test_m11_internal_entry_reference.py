from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "m11_internal_entry_reference.py"
LIVE_MAIN = ROOT / "research" / "xiaomi" / "xiaomi15ultra_main_sourcecal_live_20260909.json"
spec = importlib.util.spec_from_file_location("m11_internal_entry_reference", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class M11InternalEntryReferenceTests(unittest.TestCase):
    def test_xyz_entry_is_exact_firmware_k(self) -> None:
        basis_vectors = np.eye(3, dtype=np.float64)
        mapped = module.xyz_d50_to_internal(basis_vectors)
        np.testing.assert_allclose(mapped, module.PCS_TO_INTERNAL.T, rtol=0.0, atol=0.0)

    def test_camera_to_internal_composes_k_after_source_transform(self) -> None:
        source = np.array(
            [
                [0.5, 0.1, 0.0],
                [0.2, 0.8, 0.1],
                [0.0, 0.1, 0.7],
            ],
            dtype=np.float64,
        )
        actual = module.camera_to_internal_matrix(source)
        np.testing.assert_allclose(actual, module.PCS_TO_INTERNAL @ source, rtol=0.0, atol=0.0)

    def test_historical_basis_plus_category3_was_already_close_to_k(self) -> None:
        comparison = module.historical_entry_comparison()
        # This metric is derived from floating matrix algebra rather than a firmware
        # integer boundary, so use a precision-appropriate tolerance instead of
        # pinning platform-level last bits.
        self.assertAlmostEqual(comparison.best_scalar_to_k, 0.965408299625584, places=12)
        self.assertLess(comparison.max_abs_residual_after_scalar, 0.0132)
        self.assertLess(comparison.rms_residual_after_scalar, 0.0075)
        self.assertAlmostEqual(comparison.direct_k_relative_ev, 0.05078886518674954, places=12)

    def test_live_xiaomi_source_entry_comparison(self) -> None:
        live = json.loads(LIVE_MAIN.read_text())
        source = np.asarray(live["sourcecal2a_result"]["sensor_to_xyz_d50"], dtype=np.float64)
        comparison = module.compare_source_entries(source)

        self.assertAlmostEqual(comparison.best_scalar_old_to_direct, 0.9655747553431321, places=12)
        self.assertAlmostEqual(comparison.direct_relative_ev, 0.05054013712227328, places=12)
        self.assertLess(comparison.max_abs_residual_after_scalar, 0.02239)
        self.assertLess(comparison.rms_residual_after_scalar, 0.01197)

        np.testing.assert_allclose(
            comparison.direct_camera_to_internal,
            np.array(
                [
                    [2.469731667134, -0.022913787986, 0.35782244549],
                    [-0.05144263295, 1.073912068766, -0.09213789348],
                    [-0.145491444702, -0.547184140182, 2.56705434225],
                ]
            ),
            rtol=0.0,
            atol=5e-12,
        )

    def test_internal_entry_does_not_add_another_white_balance(self) -> None:
        # This boundary accepts XYZ D50 from the source adapter and only applies K.
        # einsum/matmul may differ by one IEEE-754 ulp, so this is a numeric parity
        # assertion rather than a byte-identity assertion.
        xyz = np.array([0.9642, 1.0, 0.8249], dtype=np.float64)
        expected = module.PCS_TO_INTERNAL @ xyz
        np.testing.assert_allclose(module.xyz_d50_to_internal(xyz), expected, rtol=0.0, atol=5e-15)


if __name__ == "__main__":
    unittest.main()
