from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "compare_m11_internal_entry_ab.py"
spec = importlib.util.spec_from_file_location("compare_m11_internal_entry_ab", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

from renderer.m11_core import reference_basis
from renderer.reference import leica_m11_reference_renderer as renderer
from tools import m11_internal_entry_reference as entry


def fixture_tables() -> renderer.Tables:
    x = np.linspace(0.0, 1.0, 33)
    return renderer.Tables(
        cc0=entry.HISTORICAL_CATEGORY3_CC0.copy(),
        cc1=np.array(
            [[1.03, -0.02, -0.01], [-0.01, 1.02, -0.01], [0.0, -0.02, 1.02]],
            dtype=np.float64,
        ),
        tone_x=x,
        tone_curves={c: np.clip(x ** (1.0 - 0.03 * c), 0.0, 1.0) for c in range(-3, 4)},
        gamma_x=x,
        gamma_y=np.sqrt(x),
    )


class M11InternalEntryABTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tables = fixture_tables()
        yy, xx = np.mgrid[0:9, 0:11]
        self.xyz = np.stack(
            [0.04 + xx / 20.0, 0.03 + yy / 18.0, 0.02 + (xx + yy) / 30.0],
            axis=-1,
        ).astype(np.float64)

    def test_ab_matches_canonical_renderer_on_both_branches(self) -> None:
        result = module.compare_xyz_buffer(self.xyz, self.tables, "standard")
        old = np.asarray(result["outputs"]["old"])
        direct = np.asarray(result["outputs"]["direct_k"])

        old_input = reference_basis.apply_xyz_d50_to_m11_reference(self.xyz)
        old_expected = renderer.render(old_input, self.tables, "standard", use_cc0=True)
        direct_input = entry.xyz_d50_to_internal(self.xyz)
        direct_expected = renderer.render(direct_input, self.tables, "standard", use_cc0=False)

        np.testing.assert_allclose(old, old_expected, rtol=0.0, atol=1e-12)
        np.testing.assert_allclose(direct, direct_expected, rtol=0.0, atol=1e-12)
        self.assertTrue(result["renderer_parity_gate"]["passed"])

    def test_only_entry_boundary_differs_before_shared_downstream(self) -> None:
        result = module.compare_xyz_buffer(self.xyz, self.tables, "standard")
        old_internal = renderer.apply_matrix(
            reference_basis.apply_xyz_d50_to_m11_reference(self.xyz), self.tables.cc0
        )
        direct_internal = entry.xyz_d50_to_internal(self.xyz)

        np.testing.assert_allclose(
            result["old_branch"]["post_cc0_internal"]["mean"],
            np.mean(old_internal.reshape(-1, 3), axis=0),
            rtol=0.0,
            atol=1e-12,
        )
        np.testing.assert_allclose(
            result["direct_k_branch"]["post_cc0_internal"]["mean"],
            np.mean(direct_internal.reshape(-1, 3), axis=0),
            rtol=0.0,
            atol=1e-12,
        )
        self.assertEqual(
            result["downstream_identical"],
            ["tone", "CC1", "YCC", "gamma_Y", "mode_chroma", "inverse_YCC", "clamp"],
        )

    def test_histograms_and_delta_diagnostics_are_complete(self) -> None:
        result = module.compare_xyz_buffer(self.xyz, self.tables, "standard")
        hist = result["old_branch"]["post_cc0_internal"]["histogram"]
        self.assertEqual(hist["bins"], 64)
        self.assertEqual(len(hist["edges"]), 65)
        self.assertEqual(len(hist["channel_counts"]), 3)
        self.assertTrue(all(len(c) == 64 for c in hist["channel_counts"]))
        self.assertIn("luma", result["direct_k_branch"]["post_tone"])
        self.assertIn("psnr_db", result["output_delta"])
        self.assertIn("fraction_abs_gt_1_code_8bit", result["output_delta"])

    def test_direct_entry_has_expected_small_relative_ev_vs_old(self) -> None:
        result = module.compare_xyz_buffer(self.xyz, self.tables, "standard")
        ev = result["empirical_post_cc0_median_luma_ev_direct_vs_old"]
        self.assertIsNotNone(ev)
        # The exact empirical value is scene/content dependent, but the closure predicts
        # a small direct-K lift rather than a large exposure discontinuity.
        self.assertGreater(ev, -0.10)
        self.assertLess(ev, 0.20)


if __name__ == "__main__":
    unittest.main()
