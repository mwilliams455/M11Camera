from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSTANTS = ROOT / "research" / "recorded" / "m11p_v03_recorded_constants.json"


class RecordedM11ConstantsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(CONSTANTS.read_text())

    def test_evidence_class_is_not_reproduced(self) -> None:
        self.assertEqual(
            self.data["evidence_class"],
            "recorded_prior_finding_not_yet_reproduced",
        )

    def test_r2y_descriptor_inventory_is_explicitly_noncanonical(self) -> None:
        r2y = self.data["r2y_database"]
        self.assertEqual(r2y["recorded_descriptor_count"], 315)
        self.assertFalse(r2y["exact_binary_layout_recovered"])
        self.assertEqual(
            set(r2y["recorded_descriptor_fields"]),
            {
                "dependency_mask",
                "descriptor_size",
                "map_size",
                "map_offset",
                "dependency_values",
            },
        )

    def test_category42_percent_relationship(self) -> None:
        states = self.data["category42_saturation"]["states"]
        for state, item in states.items():
            expected = round(512 * item["percent"] / 100) - 1
            self.assertEqual(
                item["field"],
                expected,
                msg=f"state {state} does not match recorded saturation relationship",
            )

    def test_recovered_mode_states_exist(self) -> None:
        states = self.data["category42_saturation"]["states"]
        self.assertEqual(states["-1"]["field"], 511)  # Natural ~100%
        self.assertEqual(states["0"]["field"], 588)   # Standard ~115%
        self.assertEqual(states["+1"]["field"], 665)  # Vivid ~130%

    def test_recorded_matrix_dimensions(self) -> None:
        cc0 = self.data["cc0_category3"]["matrix_q9"]
        self.assertEqual(len(cc0), 3)
        self.assertTrue(all(len(row) == 3 for row in cc0))

        low_iso = self.data["cc1_category13"]["bands_recorded"][0]
        self.assertTrue(low_iso["matrix_complete"])
        cc1 = low_iso["matrix_q9"]
        self.assertEqual(len(cc1), 3)
        self.assertTrue(all(len(row) == 3 for row in cc1))

        ycc = self.data["category24_ycc_matrix"]["signed_coefficients"]
        self.assertEqual(len(ycc), 3)
        self.assertTrue(all(len(row) == 3 for row in ycc))
        self.assertEqual(self.data["category24_ycc_matrix"]["normalization_denominator"], 256)

    def test_cc1_iso_band_inventory(self) -> None:
        cc1 = self.data["cc1_category13"]
        self.assertTrue(cc1["iso_dependent"])
        bands = cc1["bands_recorded"]
        self.assertEqual(len(bands), 4)
        self.assertEqual(bands[0]["iso_dependency_range_recorded"], "<10000")
        self.assertEqual(bands[0]["matrix_q9"][0], [1041, -372, -157])
        self.assertEqual(bands[1]["first_row_q9"], [910, -290, -108])
        self.assertEqual(bands[2]["first_row_q9"], [806, -225, -69])
        self.assertEqual(bands[3]["first_row_q9"], [715, -169, -34])

    def test_firmware_cm_exactly_matches_recorded_genuine_dng_q12(self) -> None:
        upstream = self.data["upstream_color_management_132byte_structure"]
        self.assertEqual(
            upstream["cm1_q12_ints"],
            [[2358, -546, -66], [-2488, 6300, 1785], [-403, 797, 3504]],
        )
        self.assertEqual(
            upstream["cm2_q12_ints"],
            [[1700, -326, -200], [-2354, 5409, 974], [-612, 976, 2276]],
        )
        self.assertTrue(
            upstream["genuine_m11_dng_crosscheck_2026_09_08"][
                "cm1_exactly_matches_dng_ColorMatrix1_q12"
            ]
        )
        self.assertTrue(
            upstream["genuine_m11_dng_crosscheck_2026_09_08"][
                "cm2_exactly_matches_dng_ColorMatrix2_q12"
            ]
        )

    def test_tone_luma_weights_sum_to_recorded_denominator(self) -> None:
        tone = self.data["tone"]
        self.assertEqual(sum(tone["luma_weights"]), tone["luma_weight_denominator"])


if __name__ == "__main__":
    unittest.main()
